# TrialGuard API

SaaS free trial abuse prevention API.

## Quick Start

```bash
npm install
npm start
```

## API Usage

### Verify User
```bash
POST /api/verify
Content-Type: application/json

{
  "email": "user@example.com",
  "userAgent": "Mozilla/5.0...",
  "screenResolution": "1920x1080",
  "timezone": "America/New_York",
  "languages": "en-US",
  "platform": "MacIntel",
  "canvas": "canvas-fingerprint",
  "webgl": "webgl-fingerprint"
}
```

### Response
```json
{
  "allowed": true,
  "riskScore": 15,
  "flags": [],
  "fingerprint": "a1b2c3d4...",
  "message": "Verification passed"
}
```

## Deployment

### Railway
```bash
railway login
railway init
railway up
```

### Render
Connect GitHub repo to Render.

## Environment Variables
- `PORT` - Server port (default: 3000)
