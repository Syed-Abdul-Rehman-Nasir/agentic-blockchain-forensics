'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const CONFIG_PATH = path.join(__dirname, '../config/app.config.json');

function readConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
}

function writeConfig(data) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(data, null, 2), 'utf8');
}

// GET /api/config — read current config
router.get('/', (req, res) => {
  try {
    const config = readConfig();
    // Merge runtime env values so frontend always reflects actual deployment
    config.system.channelName = process.env.CHANNEL_NAME || 'forensicchannel';
    config.system.chaincodeId = process.env.CHAINCODE_NAME || 'forensiccc';
    config.system.useRealFabric = process.env.USE_REAL_FABRIC === 'true';
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/config — write updated config (Settings UI uses this)
router.put('/', (req, res) => {
  try {
    const current = readConfig();
    // Only allow updating branding, investigator, system.mode, and chat sections
    // Never let the client overwrite system env-sourced fields
    const allowed = ['branding', 'investigator', 'chat'];
    const updated = { ...current };
    for (const key of allowed) {
      if (req.body[key] && typeof req.body[key] === 'object') {
        updated[key] = { ...current[key], ...req.body[key] };
      }
    }
    if (req.body.system?.mode) {
      updated.system = { ...current.system, mode: req.body.system.mode };
    }
    writeConfig(updated);
    res.json({ ok: true, config: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
