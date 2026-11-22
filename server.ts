import express, { type NextFunction, type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';
import { createServer as createViteServer } from 'vite';
import {
  DEPARTMENTS,
  DISPATCH_CHANNELS,
  LANGUAGES,
  ROAD_STATUSES,
  ROLES,
  ROUTES,
  ROUTES_DATA,
  SOS_TYPES,
  VEHICLE_TYPES,
  type AlertLanguage,
  type CorridorWeatherMap,
  type RoadStatusOption,
  type WeatherCurrent,
} from './src/data/corridors';
import {
  formatPkDateTime,
  isValidPkPhone,
  isValidPlate,
  isValidUsername,
  normalizePlate,
} from './src/utils/highwayLogic';
import {
  VOICE_DIR,
  generateUniqueDriverCode,
  generateUniqueSosCode,
  hashPassword,
  isAllowedLanguage,
  loadDb,
  sanitizeUser,
  saveDb,
  signSessionToken,
  verifyPassword,
  verifySessionToken,
  type StoredUser,
} from './server/store';

interface AuthedRequest extends Request {
  authUser?: StoredUser;
}

const PORT = 3000;
const OPEN_METEO_URL = 'https://api.open-meteo.com/v1/forecast';
const WEATHER_TTL_MS = 10 * 60 * 1000;

const weatherCache = new Map<string, { fetchedAt: number; data: CorridorWeatherMap }>();

function buildFallbackTelemetry(pointName: string, elevationStr: string): WeatherCurrent {
  const elevNum = Number(elevationStr.replace(/[^0-9]/g, '')) || 1000;
  const isHighPass = elevNum >= 1800 || pointName.includes('Khan Mehtarzai') || pointName.includes('Khojak');
  const isCoastalOrLowland = elevNum <= 250;

  // Deterministic variation by sector name
  let hash = 0;
  for (let i = 0; i < pointName.length; i++) {
    hash = (hash * 31 + pointName.charCodeAt(i)) % 997;
  }

  const temp = isHighPass
    ? 4 + (hash % 6)
    : isCoastalOrLowland
      ? 24 + (hash % 7)
      : 12 + (hash % 8);
  const wind = isHighPass ? 24 + (hash % 14) : 10 + (hash % 12);
  const pressure = Math.round(1016 - elevNum * 0.085);
  const humidity = isHighPass ? 58 + (hash % 18) : isCoastalOrLowland ? 52 + (hash % 20) : 34 + (hash % 18);
  const weatherCode = isHighPass && hash % 3 === 0 ? 2 : isHighPass ? 1 : 0;

  return {
    temperature_2m: temp,
    relative_humidity_2m: humidity,
    apparent_temperature: temp - 1,
    is_day: 1,
    precipitation: 0,
    rain: 0,
    showers: 0,
    snowfall: 0,
    weather_code: weatherCode,
    wind_speed_10m: wind,
    wind_gusts_10m: wind + 7,
    surface_pressure: pressure,
  };
}

async function fetchCorridorWeather(routeName: string, forceRefresh = false): Promise<{
  weather: CorridorWeatherMap;
  failedPoints: string[];
  fetchedAt: number;
}> {
  const corridor = ROUTES_DATA[routeName];
  if (!corridor) {
    return { weather: {}, failedPoints: [], fetchedAt: Date.now() };
  }

  const cached = weatherCache.get(routeName);
  if (!forceRefresh && cached && Date.now() - cached.fetchedAt < WEATHER_TTL_MS) {
    return { weather: cached.data, failedPoints: [], fetchedAt: cached.fetchedAt };
  }

  const weather: CorridorWeatherMap = {};
  const failedPoints: string[] = [];

  await Promise.all(
    corridor.points.map(async (pt) => {
      try {
        const url = new URL(OPEN_METEO_URL);
        url.searchParams.set('latitude', String(pt.lat));
        url.searchParams.set('longitude', String(pt.lon));
        url.searchParams.set(
          'current',
          'temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,rain,showers,snowfall,weather_code,wind_speed_10m,wind_gusts_10m,surface_pressure'
        );
        url.searchParams.set('timezone', 'Asia/Karachi');

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2200);
        const resp = await fetch(url.toString(), { signal: controller.signal });
        clearTimeout(timer);

        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const json = (await resp.json()) as { current?: WeatherCurrent };
        if (json && json.current) {
          weather[pt.name] = json.current;
        } else {
          failedPoints.push(pt.name);
          weather[pt.name] = buildFallbackTelemetry(pt.name, pt.elevation);
        }
      } catch {
        failedPoints.push(pt.name);
        weather[pt.name] = buildFallbackTelemetry(pt.name, pt.elevation);
      }
    })
  );

  const fetchedAt = Date.now();
  weatherCache.set(routeName, { fetchedAt, data: weather });

  return { weather, failedPoints, fetchedAt };
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  const uid = verifySessionToken(token);
  if (!uid) {
    res.status(401).json({ error: 'Session expired or invalid.' });
    return;
  }
  const db = loadDb();
  const user = db.users.find((u) => u.id === uid);
  if (!user) {
    res.status(401).json({ error: 'Operator account not found.' });
    return;
  }
  req.authUser = user;
  next();
}

function addDirToZip(zip: JSZip, absDir: string, zipRelDir: string, excludeNames: Set<string>) {
  if (!fs.existsSync(absDir)) return;
  const entries = fs.readdirSync(absDir, { withFileTypes: true });
  for (const entry of entries) {
    if (excludeNames.has(entry.name)) continue;
    const fullPath = path.join(absDir, entry.name);
    const relPath = zipRelDir ? `${zipRelDir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      addDirToZip(zip, fullPath, relPath, excludeNames);
    } else if (entry.isFile()) {
      zip.file(relPath, fs.readFileSync(fullPath));
    }
  }
}

async function startServer() {
  loadDb();

  const app = express();
  app.use(express.json({ limit: '15mb' }));

  // --- Auth Endpoints ---
  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body ?? {};
    const uname = typeof username === 'string' ? username.trim() : '';
    const pwd = typeof password === 'string' ? password : '';

    if (!uname || !pwd) {
      res.status(400).json({ error: 'Please enter both username and password.' });
      return;
    }

    const db = loadDb();
    const user = db.users.find((u) => u.username.toLowerCase() === uname.toLowerCase());
    if (!user || !verifyPassword(pwd, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid username or password. Please try again.' });
      return;
    }

    const token = signSessionToken(user.id);
    res.json({ token, user: sanitizeUser(user) });
  });

  app.post('/api/auth/signup', (req, res) => {
    const { fullName, username, department, role, password, confirmPassword } = req.body ?? {};
    const fn = typeof fullName === 'string' ? fullName.trim() : '';
    const un = typeof username === 'string' ? username.trim() : '';
    const dept = typeof department === 'string' && DEPARTMENTS.includes(department) ? department : DEPARTMENTS[0];
    const rl = typeof role === 'string' && ROLES.includes(role) ? role : ROLES[0];
    const p1 = typeof password === 'string' ? password : '';
    const p2 = typeof confirmPassword === 'string' ? confirmPassword : '';

    if (!fn || !un || !p1) {
      res.status(400).json({ error: 'Please fill all required fields.' });
      return;
    }
    if (!isValidUsername(un)) {
      res.status(400).json({ error: "Username must be 3–30 characters using only letters, numbers, '_', '.', or '-'." });
      return;
    }
    if (p1.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters long.' });
      return;
    }
    if (p1 !== p2) {
      res.status(400).json({ error: 'Passwords do not match.' });
      return;
    }

    const db = loadDb();
    if (db.users.some((u) => u.username.toLowerCase() === un.toLowerCase())) {
      res.status(409).json({ error: 'This username is already taken. Choose another username.' });
      return;
    }

    const newUser: StoredUser = {
      id: db.nextIds.user++,
      fullName: fn,
      username: un,
      department: dept,
      role: rl,
      passwordHash: hashPassword(p1),
      createdAt: formatPkDateTime(),
    };
    db.users.push(newUser);
    saveDb(db);

    const token = signSessionToken(newUser.id);
    res.status(201).json({ token, user: sanitizeUser(newUser) });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
    res.json({ user: sanitizeUser(req.authUser!) });
  });

  app.post('/api/auth/logout', (_req, res) => {
    res.json({ ok: true });
  });

  // --- Core Operational State ---
  app.get('/api/state', requireAuth, (_req, res) => {
    const db = loadDb();
    const driverMap = new Map(db.drivers.map((d) => [d.id, d.name]));
    const alertsWithRecipient = [...db.alerts]
      .sort((a, b) => b.id - a.id)
      .map((a) => ({
        ...a,
        recipientName: a.driverId ? driverMap.get(a.driverId) ?? 'Registered Driver' : 'Corridor Broadcast',
      }));

    res.json({
      drivers: [...db.drivers].sort((a, b) => b.id - a.id),
      checkpoints: db.checkpoints,
      roadStatuses: db.roadStatuses,
      alerts: alertsWithRecipient,
      sosIncidents: [...db.sosIncidents].sort((a, b) => b.id - a.id),
      voiceSamples: db.voiceSamples,
    });
  });

  // --- Live Weather Feed Proxy ---
  app.get('/api/weather', requireAuth, async (req, res) => {
    const route = typeof req.query.route === 'string' && ROUTES_DATA[req.query.route] ? req.query.route : ROUTES[0];
    const force = req.query.refresh === '1';
    const result = await fetchCorridorWeather(route, force);
    res.json({ route, ...result });
  });

  // --- Driver Registration & Check-in ---
  app.post('/api/drivers', requireAuth, (req, res) => {
    const { name, phone, vehicle, vehicleType, route, language, etaHours } = req.body ?? {};
    const fn = typeof name === 'string' ? name.trim() : '';
    const ph = typeof phone === 'string' ? phone.trim() : '';
    const vh = typeof vehicle === 'string' ? normalizePlate(vehicle) : '';
    const vt = typeof vehicleType === 'string' && VEHICLE_TYPES.includes(vehicleType) ? vehicleType : VEHICLE_TYPES[0];
    const rt = typeof route === 'string' && ROUTES_DATA[route] ? route : ROUTES[0];
    const lang: AlertLanguage = typeof language === 'string' && isAllowedLanguage(language) ? language : 'Urdu';
    const hrs = Math.max(1, Math.min(12, Number(etaHours) || 2));

    if (!fn || !ph || !vh) {
      res.status(400).json({ error: 'Please fill Driver Name, Mobile Number, and Vehicle Plate.' });
      return;
    }
    if (!isValidPkPhone(ph)) {
      res.status(400).json({ error: 'Please enter a valid Pakistani mobile number (e.g., 0300-1234567).' });
      return;
    }
    if (!isValidPlate(vh)) {
      res.status(400).json({ error: 'Please enter a valid vehicle plate number (e.g., QTA-9081).' });
      return;
    }

    const db = loadDb();
    const pts = ROUTES_DATA[rt].points;
    const startSec = pts[0].name;
    const nextSec = pts.length > 1 ? pts[1].name : pts[0].name;
    const now = new Date();
    const nowStr = formatPkDateTime(now);
    const etaStr = formatPkDateTime(new Date(now.getTime() + hrs * 3600_000));

    const newDriver = {
      id: db.nextIds.driver++,
      driverCode: generateUniqueDriverCode(db),
      name: fn,
      phone: ph,
      vehicle: vh,
      vehicleType: vt,
      route: rt,
      language: lang,
      status: 'Active on Route',
      currentSector: startSec,
      nextCheckpoint: nextSec,
      expectedEta: etaStr,
      lastCheckin: nowStr,
      createdAt: nowStr,
    };

    db.drivers.push(newDriver);
    saveDb(db);
    res.status(201).json({ driver: newDriver });
  });

  app.post('/api/drivers/:id/gate-scan', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const db = loadDb();
    const drv = db.drivers.find((d) => d.id === id);
    if (!drv) {
      res.status(404).json({ error: 'Driver not found.' });
      return;
    }
    const pts = ROUTES_DATA[drv.route]?.points ?? [];
    const names = pts.map((p) => p.name);
    const curGate = drv.nextCheckpoint || names[0] || 'Quetta';
    const idx = names.indexOf(curGate);
    const nextGate = idx >= 0 ? names[Math.min(idx + 1, names.length - 1)] : curGate;
    const now = new Date();

    drv.status = 'Verified at Gate';
    drv.currentSector = curGate;
    drv.nextCheckpoint = nextGate;
    drv.expectedEta = formatPkDateTime(new Date(now.getTime() + 2 * 3600_000));
    drv.lastCheckin = formatPkDateTime(now);

    const cp = db.checkpoints.find((c) => c.route === drv.route && c.location === curGate);
    if (cp) cp.qrScans += 1;

    saveDb(db);
    res.json({ driver: drv });
  });

  app.post('/api/drivers/:id/halt-safe', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const db = loadDb();
    const drv = db.drivers.find((d) => d.id === id);
    if (!drv) {
      res.status(404).json({ error: 'Driver not found.' });
      return;
    }
    drv.status = 'Halted at Safe Haven (Prevented)';
    drv.lastCheckin = formatPkDateTime();
    saveDb(db);
    res.json({ driver: drv });
  });

  app.post('/api/drivers/:id/confirm-safe', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const db = loadDb();
    const drv = db.drivers.find((d) => d.id === id);
    if (!drv) {
      res.status(404).json({ error: 'Driver not found.' });
      return;
    }
    const now = new Date();
    drv.status = 'Active on Route';
    drv.expectedEta = formatPkDateTime(new Date(now.getTime() + 2 * 3600_000));
    drv.lastCheckin = formatPkDateTime(now);
    saveDb(db);
    res.json({ driver: drv });
  });

  // --- SOS Dispatch & Resolution ---
  app.post('/api/sos', requireAuth, (req: AuthedRequest, res) => {
    const { driverId, route, sector, emergencyType, source, details } = req.body ?? {};
    const db = loadDb();
    const matchedDriver = driverId ? db.drivers.find((d) => d.id === Number(driverId)) : undefined;

    const rt =
      typeof route === 'string' && ROUTES_DATA[route]
        ? route
        : matchedDriver?.route && ROUTES_DATA[matchedDriver.route]
          ? matchedDriver.route
          : ROUTES[0];
    const pts = ROUTES_DATA[rt].points;
    const ptObj = pts.find((p) => p.name === sector) ?? pts[0];
    const eType =
      typeof emergencyType === 'string' && emergencyType.trim()
        ? emergencyType.trim()
        : SOS_TYPES[0];
    const srcLabel = typeof source === 'string' && source.trim() ? source.trim() : 'Quick SOS Button';
    const note =
      typeof details === 'string' && details.trim()
        ? details.trim()
        : `${eType} reported at ${ptObj.name} (${rt}) by ${req.authUser!.fullName}.`;

    const sos = {
      id: db.nextIds.sos++,
      sosCode: generateUniqueSosCode(db),
      driverId: matchedDriver?.id ?? null,
      driverName: matchedDriver?.name ?? 'Highway Commuter',
      vehicle: matchedDriver?.vehicle ?? 'SOS-UNIT',
      phone: matchedDriver?.phone ?? '0300-0000000',
      route: rt,
      sector: ptObj.name,
      lat: ptObj.lat,
      lon: ptObj.lon,
      emergencyType: eType,
      source: srcLabel,
      details: note,
      status: 'ACTIVE SOS' as const,
      dispatchedUnit: 'Rescue 1122 & Levies Dispatched',
      createdAt: formatPkDateTime(),
    };

    db.sosIncidents.push(sos);
    if (matchedDriver) {
      matchedDriver.status = 'ACTIVE SOS';
      matchedDriver.currentSector = ptObj.name;
    }
    saveDb(db);
    res.status(201).json({ sos });
  });

  app.post('/api/sos/:id/resolve', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const db = loadDb();
    const sos = db.sosIncidents.find((s) => s.id === id);
    if (!sos) {
      res.status(404).json({ error: 'SOS incident not found.' });
      return;
    }
    sos.status = 'RESOLVED';
    sos.dispatchedUnit = 'Rescue Completed';
    if (sos.driverId) {
      const drv = db.drivers.find((d) => d.id === sos.driverId);
      if (drv) drv.status = 'Safe — Assisted';
    }
    saveDb(db);
    res.json({ sos });
  });

  // --- Road Clearance Updates ---
  app.patch('/api/roads/:id', requireAuth, (req: AuthedRequest, res) => {
    const id = Number(req.params.id);
    const { status, riskScore, verifiedBy, authorityNote } = req.body ?? {};
    const db = loadDb();
    const road = db.roadStatuses.find((r) => r.id === id);
    if (!road) {
      res.status(404).json({ error: 'Road sector not found.' });
      return;
    }

    const nextStatus: RoadStatusOption =
      typeof status === 'string' && (ROAD_STATUSES as string[]).includes(status)
        ? (status as RoadStatusOption)
        : road.status;
    const parsedRisk = Number(riskScore);
    const nextRisk = Number.isFinite(parsedRisk)
      ? Math.max(1, Math.min(10, Math.trunc(parsedRisk)))
      : nextStatus.includes('Closed')
        ? 10
        : nextStatus.includes('Restricted')
          ? 6
          : 2;

    road.status = nextStatus;
    road.riskScore = nextRisk;
    if (typeof verifiedBy === 'string' && verifiedBy.trim()) {
      road.verifiedBy = verifiedBy.trim();
    } else {
      road.verifiedBy = req.authUser!.fullName;
    }
    if (typeof authorityNote === 'string' && authorityNote.trim()) {
      road.authorityNote = authorityNote.trim();
    }
    road.updatedAt = formatPkDateTime();

    saveDb(db);
    res.json({ road });
  });

  // --- Multilingual Alerts ---
  app.post('/api/alerts', requireAuth, (req, res) => {
    const { driverId, route, language, severity, message, channels } = req.body ?? {};
    const msg = typeof message === 'string' ? message.trim() : '';
    if (!msg) {
      res.status(400).json({ error: 'Alert message cannot be empty.' });
      return;
    }

    const db = loadDb();
    const rt = typeof route === 'string' && ROUTES_DATA[route] ? route : ROUTES[0];
    const lang: AlertLanguage = typeof language === 'string' && isAllowedLanguage(language) ? language : 'Urdu';
    const sev =
      severity === 'Emergency' || severity === 'Warning' || severity === 'Advisory'
        ? severity
        : 'Advisory';

    let targetDriverId: number | null = null;
    if (driverId !== undefined && driverId !== null) {
      const drv = db.drivers.find((d) => d.id === Number(driverId));
      if (!drv) {
        res.status(400).json({ error: 'Please select a valid individual driver.' });
        return;
      }
      targetDriverId = drv.id;
    }

    const validChannels = Array.isArray(channels)
      ? channels.filter((c) => typeof c === 'string' && DISPATCH_CHANNELS.includes(c))
      : [];
    const channelStr = validChannels.length > 0 ? validChannels.join(', ') : 'SMS Gateway';

    const newAlert = {
      id: db.nextIds.alert++,
      driverId: targetDriverId,
      route: rt,
      language: lang,
      severity: sev,
      message: msg,
      channel: channelStr,
      status: 'Dispatched & Logged',
      createdAt: formatPkDateTime(),
    };

    db.alerts.push(newAlert);
    saveDb(db);
    res.status(201).json({ alert: newAlert });
  });

  // --- Live Quetta -> Karachi Preventive Demo Simulator ---
  app.post('/api/demo/run', requireAuth, (_req, res) => {
    const db = loadDb();
    const now = new Date();
    const nowStr = formatPkDateTime(now);
    const etaStr = formatPkDateTime(new Date(now.getTime() + 3600_000));

    let demoDriver = db.drivers.find((d) => d.vehicle === 'QTA-9921');
    if (demoDriver) {
      demoDriver.status = 'Halted at Safe Haven (Prevented)';
      demoDriver.currentSector = 'Mastung';
      demoDriver.nextCheckpoint = 'Kalat';
      demoDriver.expectedEta = etaStr;
      demoDriver.lastCheckin = nowStr;
    } else {
      demoDriver = {
        id: db.nextIds.driver++,
        driverCode: 'BHW-9921',
        name: 'Ustad Gul Muhammad',
        phone: '0300-9214455',
        vehicle: 'QTA-9921',
        vehicleType: 'Cargo Truck',
        route: 'Quetta–Karachi (N-25)',
        language: 'Urdu',
        status: 'Halted at Safe Haven (Prevented)',
        currentSector: 'Mastung',
        nextCheckpoint: 'Kalat',
        expectedEta: etaStr,
        lastCheckin: nowStr,
        createdAt: nowStr,
      };
      db.drivers.push(demoDriver);
    }

    for (const r of db.roadStatuses) {
      if (r.route === 'Quetta–Karachi (N-25)' && (r.area === 'Kalat' || r.area === 'Khuzdar')) {
        r.status = 'Restricted — Caution';
        r.riskScore = 9;
        r.authorityNote =
          'Severe rain & flash flood risk near Kalat & Khuzdar. Heavy trucks advised to halt at Mastung Safe Haven.';
        r.updatedAt = nowStr;
      }
    }

    db.alerts = db.alerts.filter((a) => a.driverId !== demoDriver!.id);
    db.alerts.push({
      id: db.nextIds.alert++,
      driverId: demoDriver.id,
      route: 'Quetta–Karachi (N-25)',
      language: 'Urdu',
      severity: 'Emergency',
      message:
        'ہنگامی انتباہ (QTA-9921): قلات اور خضدار میں شدید بارش کے باعث خطرہ شدید (SEVERE) ہے۔ براہِ کرم مستونگ NHA سیف ہیون پر رک جائیں یا سبی-سکھر متبادل راستہ اختیار کریں۔',
      channel: 'SMS Gateway, Automated Voice Call (IVR)',
      status: 'Delivered — Truck Halted Safely',
      createdAt: nowStr,
    });

    saveDb(db);
    res.json({
      message:
        'Live Demo Executed! Truck QTA-9921 registered on N-25, warned via Urdu SMS & IVR Voice, and safely halted at Mastung Safe Haven (Hazard Prevented).',
    });
  });

  app.post('/api/demo/reset', requireAuth, (_req, res) => {
    const db = loadDb();
    const demoDriver = db.drivers.find((d) => d.vehicle === 'QTA-9921');
    if (demoDriver) {
      db.alerts = db.alerts.filter((a) => a.driverId !== demoDriver.id);
      db.drivers = db.drivers.filter((d) => d.id !== demoDriver.id);
    }
    const nowStr = formatPkDateTime();
    for (const r of db.roadStatuses) {
      if (r.route === 'Quetta–Karachi (N-25)' && (r.area === 'Kalat' || r.area === 'Khuzdar')) {
        r.status = 'Open (Verified)';
        r.riskScore = 2;
        r.authorityNote = 'Normal traffic flow; regular patrol active.';
        r.updatedAt = nowStr;
      }
    }
    saveDb(db);
    res.json({ message: 'Demo scenario reset to normal baseline.' });
  });

  // --- Custom Voice Sample Recording / Upload per Language ---
  app.post('/api/voice-samples/:lang', requireAuth, (req, res) => {
    const lang = req.params.lang;
    if (!isAllowedLanguage(lang)) {
      res.status(400).json({ error: 'Unsupported language.' });
      return;
    }
    const { audioBase64, mimeType, ext } = req.body ?? {};
    if (typeof audioBase64 !== 'string' || !audioBase64) {
      res.status(400).json({ error: 'Audio data is required.' });
      return;
    }
    const cleanExt = (typeof ext === 'string' ? ext : 'webm').toLowerCase().replace(/[^a-z0-9]/g, '');
    const safeExt = ['wav', 'mp3', 'ogg', 'webm', 'm4a'].includes(cleanExt) ? cleanExt : 'webm';
    const filename = `custom_voice_${lang.toLowerCase()}.${safeExt}`;
    const targetPath = path.resolve(VOICE_DIR, filename);
    if (!targetPath.startsWith(VOICE_DIR + path.sep)) {
      res.status(400).json({ error: 'Invalid path.' });
      return;
    }

    // Remove older variants for same language
    for (const existing of fs.readdirSync(VOICE_DIR)) {
      if (existing.startsWith(`custom_voice_${lang.toLowerCase()}.`)) {
        fs.unlinkSync(path.join(VOICE_DIR, existing));
      }
    }

    const base64Body = audioBase64.includes(',') ? audioBase64.split(',')[1] : audioBase64;
    fs.writeFileSync(targetPath, Buffer.from(base64Body, 'base64'));

    const db = loadDb();
    db.voiceSamples[lang] = {
      language: lang,
      filename,
      mimeType: typeof mimeType === 'string' && mimeType.startsWith('audio/') ? mimeType : 'audio/webm',
      updatedAt: formatPkDateTime(),
    };
    saveDb(db);
    res.status(201).json({ sample: db.voiceSamples[lang] });
  });

  app.get('/api/voice-samples/:lang', requireAuth, (req, res) => {
    const lang = req.params.lang;
    if (!isAllowedLanguage(lang)) {
      res.status(400).json({ error: 'Unsupported language.' });
      return;
    }
    const db = loadDb();
    const meta = db.voiceSamples[lang];
    if (!meta) {
      res.status(404).json({ error: 'No custom voice sample saved for this language.' });
      return;
    }
    const targetPath = path.resolve(VOICE_DIR, meta.filename);
    if (!targetPath.startsWith(VOICE_DIR + path.sep) || !fs.existsSync(targetPath)) {
      res.status(404).json({ error: 'Voice sample file not found.' });
      return;
    }
    res.setHeader('Content-Type', meta.mimeType);
    res.sendFile(targetPath);
  });

  app.delete('/api/voice-samples/:lang', requireAuth, (req, res) => {
    const lang = req.params.lang;
    if (!isAllowedLanguage(lang)) {
      res.status(400).json({ error: 'Unsupported language.' });
      return;
    }
    const db = loadDb();
    for (const existing of fs.readdirSync(VOICE_DIR)) {
      if (existing.startsWith(`custom_voice_${lang.toLowerCase()}.`)) {
        fs.unlinkSync(path.join(VOICE_DIR, existing));
      }
    }
    delete db.voiceSamples[lang];
    saveDb(db);
    res.json({ ok: true });
  });

  // --- Export Complete Project ZIP ---
  app.get('/api/export-zip', requireAuth, async (_req, res) => {
    try {
      const zip = new JSZip();
      const root = process.cwd();
      const rootFiles = [
        'package.json',
        'index.html',
        'vite.config.ts',
        'tsconfig.json',
        'metadata.json',
        'server.ts',
        '.env.example',
      ];

      for (const f of rootFiles) {
        const p = path.join(root, f);
        if (fs.existsSync(p)) {
          zip.file(f, fs.readFileSync(p));
        }
      }

      zip.file(
        'README.md',
        `# Balochistan Smart Highway & Weather Intelligence System\n` +
          `### Safety & Monitoring Command Center\n` +
          `> *"We don’t just predict dangerous journeys. We help prevent them."*\n\n` +
          `## Run Instructions\n` +
          `\`\`\`bash\nnpm install\nnpm run dev\n\`\`\`\n` +
          `Open http://localhost:3000\n` +
          `Default Login: \`admin\` / \`admin123\`\n`
      );

      const exclude = new Set(['node_modules', 'dist', '.git', '.playwright-cli', 'highway_watch_db.json', 'voice_samples']);
      addDirToZip(zip, path.join(root, 'src'), 'src', exclude);
      addDirToZip(zip, path.join(root, 'server'), 'server', exclude);
      const logoFile = path.join(root, 'public', 'assets', 'aistudio', 'logo_cf82fd85.png');
      if (fs.existsSync(logoFile)) {
        zip.file('public/assets/aistudio/logo_cf82fd85.png', fs.readFileSync(logoFile));
      }

      const buf = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="balochistan-highway-watch.zip"');
      res.send(buf);
    } catch (err) {
      res.status(500).json({ error: 'Failed to generate project zip archive.' });
    }
  });

  // --- Vite / Static Frontend Serving ---
  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Balochistan Highway Watch server listening on http://localhost:${PORT}`);
  });
}

startServer();
