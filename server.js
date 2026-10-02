'use strict';

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const { promisify } = require('util');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config({ quiet: true });

const scrypt = promisify(crypto.scrypt);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const env = process.env;
const NOW = () => Date.now();

function intEnv(name, fallback, min, max) {
  const parsed = Number.parseInt(env[name], 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max === undefined ? Number.MAX_SAFE_INTEGER : max, Math.max(min === undefined ? 0 : min, parsed));
}

function floatEnv(name, fallback) {
  const parsed = Number.parseFloat(env[name]);
  return Number.isFinite(parsed) ? Math.min(1, Math.max(0, parsed)) : fallback;
}

function listEnv(name) {
  return (env[name] || '').split(',').map((item) => item.trim()).filter(Boolean);
}

const IS_PRODUCTION = env.NODE_ENV === 'production';

function resolveSecret(name) {
  const value = env[name];
  if (value && value.length >= 16) return value;
  if (IS_PRODUCTION) {
    console.error(`${name} must be set to a random value of at least 16 characters`);
    process.exit(1);
  }
  console.warn(`${name} is not set; using an ephemeral development secret`);
  return crypto.randomBytes(32).toString('hex');
}

const SESSION_SECRET = resolveSecret('SESSION_SECRET');
const IP_HASH_SECRET = resolveSecret('IP_HASH_SECRET');
const ADMIN_SECRET = env.ADMIN_SECRET && env.ADMIN_SECRET.length >= 16 ? env.ADMIN_SECRET : '';

const config = {
  production: IS_PRODUCTION,
  port: intEnv('PORT', 3000, 1, 65535),
  mongoUri: env.MONGODB_URI || 'mongodb://localhost:27017/novatalk',
  sessionTtlMs: intEnv('SESSION_EXPIRY', 86400, 300) * 1000,
  identityRetentionMs: intEnv('IDENTITY_RETENTION', 2592000, 3600) * 1000,
  messageRetentionMs: intEnv('MESSAGE_RETENTION', 2592000, 3600) * 1000,
  transferLimit: intEnv('FILE_TRANSFER_LIMIT', 52428800, 1),
  stunServers: listEnv('STUN_SERVER'),
  turnServers: listEnv('TURN_SERVER'),
  turnUsername: env.TURN_USERNAME || '',
  turnPassword: env.TURN_PASSWORD || '',
  nsfw: {
    blockThreshold: floatEnv('NSFW_BLOCK_THRESHOLD', 0.85),
    reviewThreshold: floatEnv('NSFW_REVIEW_THRESHOLD', 0.65),
    warningLimit: intEnv('NSFW_WARNING_LIMIT', 1, 1),
    tempBanLimit: intEnv('NSFW_TEMP_BAN_LIMIT', 2, 1),
    permanentBanLimit: intEnv('NSFW_PERMANENT_BAN_LIMIT', 3, 1),
    reviewEscalation: intEnv('NSFW_REVIEW_ESCALATION', 3, 2)
  },
  tempBanMs: intEnv('TEMP_BAN_DURATION', 86400, 60) * 1000,
  longBanMs: intEnv('LONG_BAN_DURATION', 2592000, 3600) * 1000,
  ipBanMaxMs: intEnv('IP_BAN_MAX_DURATION', 86400, 60) * 1000,
  reportRestrictThreshold: intEnv('REPORT_RESTRICT_THRESHOLD', 5, 2),
  allowedOrigins: listEnv('ALLOWED_ORIGINS'),
  trustProxyHops: intEnv('TRUST_PROXY', 0, 0, 5),
  maxCiphertext: intEnv('MAX_CIPHERTEXT_LENGTH', 32768, 256, 60000),
  maxGroupMembers: intEnv('MAX_GROUP_MEMBERS', 100, 3, 500),
  maxRoomMembers: intEnv('MAX_ROOM_MEMBERS', 100, 2, 500),
  roomMaxLifetimeMs: intEnv('ROOM_MAX_LIFETIME', 86400, 300) * 1000,
  roomsPerIdentity: intEnv('ROOMS_PER_IDENTITY', 3, 1),
  queueTimeoutMs: intEnv('MATCH_QUEUE_TIMEOUT', 120, 10) * 1000,
  maxQueueSize: intEnv('MAX_QUEUE_SIZE', 10000, 10),
  maxSocketsPerIdentity: intEnv('MAX_SOCKETS_PER_IDENTITY', 5, 1)
};

const TIMING = {
  callRingMs: 45000,
  transferRequestMs: 90000,
  transferMaxMs: 1800000,
  disconnectGraceMs: 15000,
  interestWaitMs: 8000,
  peerRequestMs: 120000,
  matchGraceMs: 600000,
  matchConversationMs: 86400000,
  warningMs: 604800000,
  rematchBlockMs: 60000,
  sessionCacheMs: 30000,
  restrictionCacheMs: 15000
};

const ROLE_RANK = { owner: 4, admin: 3, moderator: 2, member: 1 };
const ROLES = Object.keys(ROLE_RANK);
const MATCH_MODES = ['text', 'video'];
const REPORT_CATEGORIES = ['spam', 'harassment', 'sexual_content', 'scam', 'hate', 'illegal_content', 'other'];
const RESTRICTIONS = ['session', 'matchmaking', 'rooms', 'messaging', 'calls', 'transfers'];
const FULL_RESTRICTIONS = ['matchmaking', 'rooms', 'messaging', 'calls', 'transfers'];
const BAN_TYPES = ['warning', 'temporary', 'long_term', 'permanent'];
const KEY_ALGORITHMS = ['ECDH-P256', 'ECDH-P384', 'ECDH-P521'];
const KEY_HISTORY_LIMIT = 20;
const SUGGESTED_INTERESTS = ['Gaming', 'Music', 'Movies', 'Coding', 'Anime', 'Sports', 'Technology', 'Art', 'Photography', 'Education'];

const ID_PATTERN = /^[A-Za-z0-9_-]{6,64}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/_-]+={0,2}$/;
const STRICT_CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const MULTILINE_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const INTEREST_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} +#&-]{0,23}$/u;
const MIME_PATTERN = /^[a-z0-9!#$&^_.+-]{1,64}\/[a-z0-9!#$&^_.+-]{1,64}$/i;

const ADJECTIVES = ['Silent', 'Blue', 'Midnight', 'Silver', 'Quiet', 'Shadow', 'Red', 'Neon', 'Golden', 'Misty', 'Amber', 'Crimson', 'Lunar', 'Solar', 'Swift', 'Gentle', 'Frosty', 'Velvet', 'Cosmic', 'Hidden'];
const ANIMALS = ['Fox', 'Raven', 'Wolf', 'Panda', 'Tiger', 'Owl', 'Falcon', 'Bear', 'Lynx', 'Otter', 'Heron', 'Cobra', 'Badger', 'Koala', 'Dolphin', 'Panther', 'Sparrow', 'Hawk', 'Stag', 'Hare'];

class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra || null;
  }
}

const fail = (status, code, message, extra) => new HttpError(status, code, message, extra);

const randomId = (prefix, bytes = 12) => `${prefix}_${crypto.randomBytes(bytes).toString('base64url')}`;
const hmacHex = (label, value) => crypto.createHmac('sha256', IP_HASH_SECRET).update(`${label}:${value}`).digest('hex').slice(0, 40);
const ipHashOf = (ip) => hmacHex('ip', ip);
const identityHashOf = (anonymousId) => hmacHex('id', anonymousId);
const deviceHashOf = (key) => hmacHex('dev', key);
const tokenHashOf = (token) => crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex');
const shortId = (id) => (typeof id === 'string' ? id.slice(-6) : 'unknown');
const randomDisplayName = () => `${ADJECTIVES[crypto.randomInt(ADJECTIVES.length)]} ${ANIMALS[crypto.randomInt(ANIMALS.length)]}`;

function safeEqual(a, b) {
  const left = crypto.createHash('sha256').update(String(a)).digest();
  const right = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(left, right);
}

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function asObject(value) {
  if (value === undefined || value === null) return {};
  if (!isPlainObject(value)) throw fail(400, 'invalid_payload', 'Payload must be a JSON object');
  return value;
}

function readString(source, field, options = {}) {
  const value = source[field];
  if (value === undefined || value === null) {
    if (options.optional) return undefined;
    throw fail(400, 'invalid_payload', `${field} is required`);
  }
  if (typeof value !== 'string') throw fail(400, 'invalid_payload', `${field} must be a string`);
  const min = options.min === undefined ? 1 : options.min;
  const max = options.max === undefined ? 255 : options.max;
  if (value.length < min || value.length > max) throw fail(400, 'invalid_payload', `${field} has an invalid length`);
  if (options.pattern && !options.pattern.test(value)) throw fail(400, 'invalid_payload', `${field} has an invalid format`);
  if ((options.multiline ? MULTILINE_CONTROL : STRICT_CONTROL).test(value)) throw fail(400, 'invalid_payload', `${field} contains invalid characters`);
  return value;
}

function readId(source, field, options = {}) {
  return readString(source, field, { ...options, min: 6, max: 64, pattern: ID_PATTERN });
}

function readInt(source, field, options = {}) {
  const value = source[field];
  if (value === undefined || value === null) {
    if (options.optional) return options.fallback;
    throw fail(400, 'invalid_payload', `${field} is required`);
  }
  if (!Number.isInteger(value)) throw fail(400, 'invalid_payload', `${field} must be an integer`);
  if (options.min !== undefined && value < options.min) throw fail(400, 'invalid_payload', `${field} is too small`);
  if (options.max !== undefined && value > options.max) throw fail(400, 'invalid_payload', `${field} is too large`);
  return value;
}

function readNumber(source, field, min, max) {
  const value = source[field];
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) throw fail(400, 'invalid_payload', `${field} is invalid`);
  return value;
}

function readBool(source, field, fallback) {
  const value = source[field];
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'boolean') throw fail(400, 'invalid_payload', `${field} must be a boolean`);
  return value;
}

function readEnum(source, field, allowed, options = {}) {
  const value = source[field];
  if (value === undefined || value === null) {
    if (options.optional) return undefined;
    throw fail(400, 'invalid_payload', `${field} is required`);
  }
  if (typeof value !== 'string' || !allowed.includes(value)) throw fail(400, 'invalid_payload', `${field} is invalid`);
  return value;
}

function readIdArray(source, field, options = {}) {
  const value = source[field];
  if (value === undefined || value === null) {
    if (options.optional) return undefined;
    throw fail(400, 'invalid_payload', `${field} is required`);
  }
  if (!Array.isArray(value) || value.length > (options.max || 50) || (options.min && value.length < options.min)) throw fail(400, 'invalid_payload', `${field} is invalid`);
  return [...new Set(value.map((item) => {
    if (typeof item !== 'string' || !ID_PATTERN.test(item)) throw fail(400, 'invalid_payload', `${field} contains an invalid id`);
    return item;
  }))];
}

function clampQueryInt(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function sanitizeDisplayName(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') throw fail(400, 'invalid_display_name', 'displayName must be a string');
  const cleaned = value
    .normalize('NFKC')
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned.length < 1 || cleaned.length > 32) throw fail(400, 'invalid_display_name', 'displayName must be 1 to 32 characters');
  return cleaned;
}

function sanitizeFileName(value) {
  const cleaned = value.normalize('NFKC').replace(/[\u0000-\u001f\u007f-\u009f\\/:*?"<>|]/g, '_').trim();
  if (!cleaned) throw fail(400, 'invalid_payload', 'fileName is invalid');
  return cleaned.slice(0, 255);
}

function log(message, fields) {
  const parts = [new Date().toISOString(), message];
  if (fields) {
    for (const [key, value] of Object.entries(fields)) {
      if (value !== undefined && value !== null) parts.push(`${key}=${String(value).slice(0, 64)}`);
    }
  }
  console.log(parts.join(' '));
}

function logError(message, err) {
  const name = err && err.name ? err.name : 'Error';
  const code = err && err.code ? err.code : '';
  if (config.production) console.error(new Date().toISOString(), message, name, code);
  else console.error(new Date().toISOString(), message, err && err.stack ? err.stack : name);
}

const RATE_RULES = {
  api: { ip: [900, 60000] },
  session: { ip: [40, 600000], device: [10, 3600000] },
  keyRotate: { identity: [10, 3600000], ip: [60, 3600000] },
  matchmaking: { identity: [30, 60000], ip: [200, 60000] },
  message: { identity: [90, 60000], ip: [1200, 60000] },
  read: { identity: [240, 60000], ip: [1200, 60000] },
  conversation: { identity: [30, 3600000], ip: [200, 3600000] },
  roomCreate: { identity: [5, 3600000], ip: [40, 3600000] },
  roomJoin: { identity: [30, 600000], ip: [200, 600000] },
  block: { identity: [60, 3600000] },
  report: { identity: [10, 3600000], ip: [80, 3600000] },
  call: { identity: [20, 600000], ip: [200, 600000] },
  signal: { identity: [900, 60000] },
  transfer: { identity: [20, 600000], ip: [200, 600000] },
  peer: { identity: [20, 600000], ip: [100, 600000] },
  typing: { identity: [40, 10000] },
  moderation: { identity: [30, 3600000], ip: [200, 3600000] },
  socketConnect: { ip: [120, 60000], identity: [30, 60000] },
  socketEvent: { identity: [600, 10000] },
  adminAuth: { ip: [30, 600000] }
};

const MAX_RATE_ENTRIES = 200000;
const rateBuckets = new Map();

function hit(key, limit, windowMs) {
  const now = NOW();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateBuckets.set(key, bucket);
    if (rateBuckets.size > MAX_RATE_ENTRIES) {
      let remove = Math.ceil(MAX_RATE_ENTRIES * 0.1);
      for (const oldKey of rateBuckets.keys()) {
        rateBuckets.delete(oldKey);
        if (--remove <= 0) break;
      }
    }
  }
  bucket.count += 1;
  return bucket.count <= limit ? 0 : bucket.resetAt - now;
}

function checkRate(rule, ctx, scope = '') {
  const definition = RATE_RULES[rule];
  const dimensions = { ip: ctx.ipHash, identity: ctx.anonymousId, device: ctx.deviceHash };
  let retry = 0;
  for (const [dimension, config_] of Object.entries(definition)) {
    const value = dimensions[dimension];
    if (!value) continue;
    retry = Math.max(retry, hit(`${rule}:${dimension}:${scope}:${value}`, config_[0], config_[1]));
  }
  if (retry > 0) throw fail(429, 'rate_limited', 'Too many requests', { retryAfterMs: retry });
}

function sweepRateBuckets() {
  const now = NOW();
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(key);
  }
}

mongoose.set('strictQuery', true);
mongoose.set('bufferTimeoutMS', 2500);

const { Schema } = mongoose;
const schemaOptions = { versionKey: false };
const str = { type: String };
const reqStr = { type: String, required: true };

const userSessionSchema = new Schema({
  tokenHash: { ...reqStr, unique: true },
  anonymousId: { ...reqStr, index: true },
  identityHash: reqStr,
  deviceHash: { type: String, default: null },
  ipHash: str,
  createdAt: { type: Date, default: Date.now },
  lastSeenAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
userSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const keySchema = new Schema({
  version: Number,
  publicKey: String,
  algorithm: String,
  createdAt: Date
}, { _id: false });

const anonymousIdentitySchema = new Schema({
  anonymousId: { ...reqStr, unique: true },
  identityHash: { ...reqStr, unique: true },
  displayName: reqStr,
  keys: { type: [keySchema], default: [] },
  currentKeyVersion: { type: Number, default: 0 },
  violationCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  lastSeenAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
anonymousIdentitySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const deviceIdentitySchema = new Schema({
  deviceHash: { ...reqStr, unique: true },
  anonymousIds: { type: [String], default: [] },
  sessionCount: { type: Number, default: 0 },
  violationCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  lastSeenAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
deviceIdentitySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const conversationSchema = new Schema({
  conversationId: { ...reqStr, unique: true },
  type: { type: String, enum: ['direct', 'group'], required: true },
  origin: { type: String, enum: ['direct', 'group', 'match', 'room'], default: 'direct' },
  title: { type: String, default: null },
  createdBy: str,
  directKey: { type: String },
  roomId: { type: String, default: null },
  matchId: { type: String, default: null },
  ephemeral: { type: Boolean, default: false },
  memberCount: { type: Number, default: 0 },
  settings: {
    allowMemberInvites: { type: Boolean, default: false },
    onlyAdminsCanMessage: { type: Boolean, default: false }
  },
  lastMessageAt: { type: Date, default: null },
  activityAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date }
}, schemaOptions);
conversationSchema.index({ directKey: 1 }, { unique: true, partialFilterExpression: { directKey: { $type: 'string' } } });
conversationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 3600 });
conversationSchema.index({ activityAt: -1 });

const conversationMemberSchema = new Schema({
  conversationId: reqStr,
  anonymousId: reqStr,
  role: { type: String, enum: ROLES, default: 'member' },
  joinedAt: { type: Date, default: Date.now },
  lastReadAt: { type: Date, default: null },
  lastReadMessageId: { type: String, default: null }
}, schemaOptions);
conversationMemberSchema.index({ conversationId: 1, anonymousId: 1 }, { unique: true });
conversationMemberSchema.index({ anonymousId: 1, joinedAt: -1 });

const messageSchema = new Schema({
  messageId: { ...reqStr, unique: true },
  conversationId: reqStr,
  senderId: reqStr,
  recipientId: { type: String, default: null },
  ciphertext: reqStr,
  nonce: str,
  keyVersion: { type: Number, required: true },
  recipientKeyVersion: { type: Number, default: null },
  clientMessageId: { type: String },
  replyTo: { type: String, default: null },
  deliveredTo: { type: [new Schema({ anonymousId: String, at: Date }, { _id: false })], default: [] },
  createdAt: { type: Date, default: Date.now },
  deletedAt: { type: Date, default: null },
  deletedBy: { type: String, default: null },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
messageSchema.index({ conversationId: 1, createdAt: -1, messageId: -1 });
messageSchema.index({ conversationId: 1, senderId: 1, clientMessageId: 1 }, { unique: true, partialFilterExpression: { clientMessageId: { $type: 'string' } } });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const messageReactionSchema = new Schema({
  messageId: reqStr,
  conversationId: reqStr,
  anonymousId: reqStr,
  reactionId: reqStr,
  ciphertext: reqStr,
  nonce: str,
  keyVersion: Number,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
messageReactionSchema.index({ messageId: 1, anonymousId: 1, reactionId: 1 }, { unique: true });
messageReactionSchema.index({ conversationId: 1 });
messageReactionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const roomSchema = new Schema({
  roomId: { ...reqStr, unique: true },
  ownerId: { ...reqStr, index: true },
  name: { type: String, default: null },
  pinHash: { type: String, default: null },
  pinSalt: { type: String, default: null },
  maxMembers: { type: Number, required: true },
  memberCount: { type: Number, default: 0 },
  allowCalls: { type: Boolean, default: true },
  allowTransfers: { type: Boolean, default: true },
  allowVoiceMessages: { type: Boolean, default: true },
  conversationId: reqStr,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
roomSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 3600 });

const roomMemberSchema = new Schema({
  roomId: reqStr,
  anonymousId: reqStr,
  joinedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
roomMemberSchema.index({ roomId: 1, anonymousId: 1 }, { unique: true });
roomMemberSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 3600 });

const matchSchema = new Schema({
  matchId: { ...reqStr, unique: true },
  mode: { type: String, enum: MATCH_MODES, required: true },
  participants: { type: [String], index: true },
  initiatorId: str,
  conversationId: str,
  callId: { type: String, default: null },
  sharedInterests: { type: [String], default: [] },
  status: { type: String, enum: ['active', 'ended'], default: 'active' },
  endReason: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
  endedAt: { type: Date, default: null },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
matchSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const blockSchema = new Schema({
  blockerId: reqStr,
  blockedId: reqStr,
  createdAt: { type: Date, default: Date.now }
}, schemaOptions);
blockSchema.index({ blockerId: 1, blockedId: 1 }, { unique: true });
blockSchema.index({ blockedId: 1 });

const reportSchema = new Schema({
  reportId: { ...reqStr, unique: true },
  reporterHash: reqStr,
  reportedHash: reqStr,
  category: { type: String, enum: REPORT_CATEGORIES, required: true },
  conversationId: { type: String, default: null },
  description: { type: String, default: null },
  status: { type: String, enum: ['open', 'reviewed', 'dismissed'], default: 'open' },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
reportSchema.index({ reportedHash: 1, createdAt: -1 });
reportSchema.index({ reporterHash: 1, reportedHash: 1, category: 1, createdAt: -1 });
reportSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const reservationSchema = new Schema({
  transferId: String,
  bytes: Number,
  expiresAt: Date
}, { _id: false });

const transferQuotaSchema = new Schema({
  conversationId: reqStr,
  senderId: reqStr,
  receiverId: { type: String, default: null },
  usedBytes: { type: Number, default: 0 },
  reservedBytes: { type: Number, default: 0 },
  limitBytes: { type: Number, required: true },
  reservations: { type: [reservationSchema], default: [] },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, schemaOptions);
transferQuotaSchema.index({ conversationId: 1, senderId: 1 }, { unique: true });
transferQuotaSchema.index({ 'reservations.expiresAt': 1 });

const callSessionSchema = new Schema({
  callId: { ...reqStr, unique: true },
  conversationId: reqStr,
  callerId: reqStr,
  receiverId: reqStr,
  type: { type: String, enum: ['voice', 'video'], required: true },
  status: { type: String, enum: ['ringing', 'active', 'ended', 'rejected', 'missed', 'cancelled'], default: 'ringing' },
  startedAt: { type: Date, default: Date.now },
  answeredAt: { type: Date, default: null },
  endedAt: { type: Date, default: null },
  endReason: { type: String, default: null },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
callSessionSchema.index({ status: 1 });
callSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const moderationEventSchema = new Schema({
  eventId: { ...reqStr, unique: true },
  anonymousIdentityHash: reqStr,
  reporterIdentityHash: reqStr,
  conversationId: reqStr,
  transferId: reqStr,
  type: { type: String, enum: ['nsfw_detected', 'nsfw_blocked_locally'], required: true },
  category: str,
  confidence: Number,
  action: { type: String, enum: ['ignored', 'recorded', 'review', 'confirmed', 'duplicate'], required: true },
  violationCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, schemaOptions);
moderationEventSchema.index({ transferId: 1, type: 1 }, { unique: true });
moderationEventSchema.index({ anonymousIdentityHash: 1, createdAt: -1 });
moderationEventSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const banSchema = new Schema({
  banId: { ...reqStr, unique: true },
  scope: { type: String, enum: ['identity', 'device', 'ip', 'combined'], required: true },
  anonymousIdentityHash: { type: String, default: null },
  deviceIdentityHash: { type: String, default: null },
  ipHash: { type: String, default: null },
  banType: { type: String, enum: BAN_TYPES, required: true },
  restrictions: { type: [String], default: [] },
  reason: { type: String, default: null },
  source: { type: String, enum: ['system', 'reports', 'admin'], default: 'system' },
  violationCount: { type: Number, default: 0 },
  status: { type: String, enum: ['active', 'expired', 'lifted'], default: 'active' },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date }
}, schemaOptions);
banSchema.index({ status: 1, expiresAt: 1 });
banSchema.index({ anonymousIdentityHash: 1, status: 1 });
banSchema.index({ deviceIdentityHash: 1, status: 1 });
banSchema.index({ ipHash: 1, status: 1 });
banSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 2592000 });

const UserSession = mongoose.model('UserSession', userSessionSchema);
const AnonymousIdentity = mongoose.model('AnonymousIdentity', anonymousIdentitySchema);
const DeviceIdentity = mongoose.model('DeviceIdentity', deviceIdentitySchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const ConversationMember = mongoose.model('ConversationMember', conversationMemberSchema);
const Message = mongoose.model('Message', messageSchema);
const MessageReaction = mongoose.model('MessageReaction', messageReactionSchema);
const Room = mongoose.model('Room', roomSchema);
const RoomMember = mongoose.model('RoomMember', roomMemberSchema);
const Match = mongoose.model('Match', matchSchema);
const Block = mongoose.model('Block', blockSchema);
const Report = mongoose.model('Report', reportSchema);
const TransferQuota = mongoose.model('TransferQuota', transferQuotaSchema);
const CallSession = mongoose.model('CallSession', callSessionSchema);
const ModerationEvent = mongoose.model('ModerationEvent', moderationEventSchema);
const Ban = mongoose.model('Ban', banSchema);

const dbReady = () => mongoose.connection.readyState === 1;

const userSockets = new Map();
const disconnectTimers = new Map();
const sessionCache = new Map();
const restrictionCache = new Map();
const matchQueues = { text: new Map(), video: new Map() };
const waitingIndex = new Map();
const activeMatches = new Map();
const userMatch = new Map();
const recentPairs = new Map();
const activeCalls = new Map();
const userCall = new Map();
const transfers = new Map();
const userTransfers = new Map();
const recentTransfers = new Map();
const peerRequests = new Map();
const pinAttempts = new Map();

const app = express();
const server = http.createServer(app);

function originAllowed(origin) {
  if (!origin) return true;
  if (config.allowedOrigins.includes(origin)) return true;
  if (!config.production) {
    try {
      return ['localhost', '127.0.0.1', '[::1]'].includes(new URL(origin).hostname);
    } catch (err) {
      return false;
    }
  }
  return false;
}

const io = new Server(server, {
  maxHttpBufferSize: 131072,
  pingInterval: 20000,
  pingTimeout: 25000,
  connectTimeout: 15000,
  cors: {
    origin: (origin, callback) => callback(null, originAllowed(origin)),
    credentials: true
  },
  allowRequest: (req, callback) => callback(null, originAllowed(req.headers.origin))
});

const emitToUser = (id, event, payload) => io.to(`user:${id}`).emit(event, payload);
const emitToConversation = (id, event, payload) => io.to(`conv:${id}`).emit(event, payload);
const joinConversationRooms = (userId, conversationId) => io.in(`user:${userId}`).socketsJoin(`conv:${conversationId}`);
const leaveConversationRooms = (userId, conversationId) => io.in(`user:${userId}`).socketsLeave(`conv:${conversationId}`);
const isOnline = (id) => { const set = userSockets.get(id); return !!set && set.size > 0; };

function normalizeIp(raw) {
  if (!raw) return 'unknown';
  let ip = String(raw).trim();
  if (ip.startsWith('::ffff:') && ip.includes('.')) ip = ip.slice(7);
  if (!ip.includes(':')) return ip;
  const halves = ip.split('%')[0].split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length > 1 ? 8 - head.length - tail.length : 0;
  const groups = head.concat(new Array(Math.max(0, missing)).fill('0'), tail);
  return `${groups.slice(0, 4).map((group) => group.padStart(4, '0')).join(':')}/64`;
}

function resolveIp(headers, remoteAddress) {
  let candidate = remoteAddress;
  if (config.trustProxyHops > 0) {
    const forwarded = String(headers['x-forwarded-for'] || '').split(',').map((item) => item.trim()).filter(Boolean);
    const index = forwarded.length - config.trustProxyHops;
    if (index >= 0) candidate = forwarded[index];
  }
  return normalizeIp(candidate);
}

const RESTRICTION_LABELS = {
  session: 'session',
  matchmaking: 'matchmaking',
  rooms: 'rooms',
  messaging: 'messaging',
  calls: 'calls',
  transfers: 'transfers'
};

function banClauses(ctx) {
  const clauses = [];
  if (ctx.identityHash) clauses.push({ scope: 'identity', anonymousIdentityHash: ctx.identityHash });
  if (ctx.deviceHash) clauses.push({ scope: 'device', deviceIdentityHash: ctx.deviceHash });
  if (ctx.ipHash) {
    clauses.push({ scope: 'ip', ipHash: ctx.ipHash });
    const linked = [];
    if (ctx.identityHash) linked.push({ anonymousIdentityHash: ctx.identityHash });
    if (ctx.deviceHash) linked.push({ deviceIdentityHash: ctx.deviceHash });
    if (linked.length) clauses.push({ scope: 'combined', ipHash: ctx.ipHash, $or: linked });
  }
  return clauses;
}

function banMatchesCtx(ban, ctx) {
  const identityMatch = !!ctx.identityHash && ban.anonymousIdentityHash === ctx.identityHash;
  const deviceMatch = !!ctx.deviceHash && ban.deviceIdentityHash === ctx.deviceHash;
  const ipMatch = !!ctx.ipHash && ban.ipHash === ctx.ipHash;
  switch (ban.scope) {
    case 'identity': return identityMatch;
    case 'device': return deviceMatch;
    case 'ip': return ipMatch;
    case 'combined': return ipMatch && (identityMatch || deviceMatch);
    default: return false;
  }
}

async function loadRestrictions(ctx) {
  const key = `${ctx.identityHash || ''}|${ctx.deviceHash || ''}|${ctx.ipHash || ''}`;
  const cached = restrictionCache.get(key);
  if (cached && cached.at + TIMING.restrictionCacheMs > NOW()) return cached.value;
  const clauses = banClauses(ctx);
  const value = { set: new Set(), bans: [] };
  if (clauses.length) {
    const now = new Date();
    try {
      const bans = await Ban.find({
        status: 'active',
        $and: [{ $or: clauses }, { $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }] }]
      }).lean();
      for (const ban of bans) {
        ban.restrictions.forEach((item) => value.set.add(item));
        value.bans.push(ban);
      }
    } catch (err) {
      if (cached) return cached.value;
      throw err;
    }
  }
  restrictionCache.set(key, { at: NOW(), value });
  return value;
}

async function assertAllowed(ctx, action) {
  const restrictions = await loadRestrictions(ctx);
  if (restrictions.set.has(action)) {
    const ban = restrictions.bans.find((item) => item.restrictions.includes(action));
    throw fail(403, 'restricted', `This action is restricted (${RESTRICTION_LABELS[action]})`, {
      restriction: action,
      banType: ban ? ban.banType : undefined,
      expiresAt: ban && ban.expiresAt ? ban.expiresAt : null
    });
  }
}

async function resolveSession(token, ipHash) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 128 || !/^[A-Za-z0-9_-]+$/.test(token)) {
    throw fail(401, 'invalid_session', 'Invalid session token');
  }
  const tokenHash = tokenHashOf(token);
  const now = NOW();
  let record;
  const cached = sessionCache.get(tokenHash);
  if (cached && cached.cachedAt + TIMING.sessionCacheMs > now) {
    record = cached;
  } else {
    const doc = await UserSession.findOne({ tokenHash }).lean();
    if (!doc) {
      sessionCache.delete(tokenHash);
      throw fail(401, 'invalid_session', 'Invalid session token');
    }
    record = {
      tokenHash,
      anonymousId: doc.anonymousId,
      identityHash: doc.identityHash,
      deviceHash: doc.deviceHash || null,
      expiresAt: doc.expiresAt.getTime(),
      cachedAt: now,
      touchedAt: doc.lastSeenAt ? doc.lastSeenAt.getTime() : 0
    };
    sessionCache.set(tokenHash, record);
  }
  if (record.expiresAt <= now) {
    sessionCache.delete(tokenHash);
    throw fail(401, 'session_expired', 'Session expired');
  }
  if (now - record.touchedAt > 300000) {
    record.touchedAt = now;
    UserSession.updateOne({ tokenHash }, { $set: { lastSeenAt: new Date(now) } }).catch(() => {});
  }
  return {
    anonymousId: record.anonymousId,
    identityHash: record.identityHash,
    deviceHash: record.deviceHash,
    ipHash,
    tokenHash,
    expiresAt: record.expiresAt
  };
}

const NETWORK_ERROR_NAMES = new Set(['MongoNetworkError', 'MongoNetworkTimeoutError', 'MongoServerSelectionError', 'MongooseServerSelectionError', 'MongoNotConnectedError', 'MongoTopologyClosedError', 'MongoPoolClearedError', 'MongoPoolClosedError']);

function isDbError(err) {
  if (!err) return false;
  if (NETWORK_ERROR_NAMES.has(err.name)) return true;
  return typeof err.message === 'string' && /buffering timed out|not connected|topology/i.test(err.message);
}

function describeError(err) {
  if (err instanceof HttpError) return { status: err.status, code: err.code, message: err.message, ...(err.extra || {}) };
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) return { status: 400, code: 'invalid_json', message: 'Request body must be valid JSON' };
  if (isDbError(err) || !dbReady()) return { status: 503, code: 'db_unavailable', message: 'Database temporarily unavailable' };
  if (err && err.code === 11000) return { status: 409, code: 'conflict', message: 'Resource already exists' };
  if (err && (err.name === 'ValidationError' || err.name === 'CastError')) return { status: 400, code: 'invalid_payload', message: 'Invalid data' };
  if (err && (err.type === 'entity.too.large' || err.status === 413)) return { status: 413, code: 'payload_too_large', message: 'Request body is too large' };
  logError('unexpected error', err);
  return { status: 500, code: 'internal_error', message: 'Internal server error' };
}

async function isBlockedBetween(a, b) {
  const found = await Block.exists({ $or: [{ blockerId: a, blockedId: b }, { blockerId: b, blockedId: a }] });
  return !!found;
}

async function loadBlockedSet(anonymousId) {
  const blocks = await Block.find({ $or: [{ blockerId: anonymousId }, { blockedId: anonymousId }] }).select('blockerId blockedId').lean();
  return new Set(blocks.map((block) => (block.blockerId === anonymousId ? block.blockedId : block.blockerId)));
}

function punishmentFor(count) {
  const { warningLimit, tempBanLimit, permanentBanLimit } = config.nsfw;
  if (count <= warningLimit) return { banType: 'warning', restrictions: [], durationMs: TIMING.warningMs };
  if (count <= tempBanLimit) return { banType: 'temporary', restrictions: ['transfers'], durationMs: config.tempBanMs };
  if (count <= permanentBanLimit) return { banType: 'temporary', restrictions: FULL_RESTRICTIONS.slice(), durationMs: config.tempBanMs * 7 };
  if (count < permanentBanLimit * 2) return { banType: 'long_term', restrictions: FULL_RESTRICTIONS.slice(), durationMs: config.longBanMs };
  return { banType: 'permanent', restrictions: FULL_RESTRICTIONS.concat('session'), durationMs: null };
}

async function createBan(fields) {
  const ban = await Ban.create({
    banId: randomId('ban', 9),
    scope: fields.scope,
    anonymousIdentityHash: fields.identityHash || null,
    deviceIdentityHash: fields.deviceHash || null,
    ipHash: fields.ipHash || null,
    banType: fields.banType,
    restrictions: fields.restrictions,
    reason: fields.reason || null,
    source: fields.source || 'system',
    violationCount: fields.violationCount || 0,
    status: 'active',
    expiresAt: fields.durationMs ? new Date(NOW() + fields.durationMs) : undefined
  });
  restrictionCache.clear();
  log('ban created', { ban: shortId(ban.banId), type: ban.banType, scope: ban.scope, source: ban.source });
  return ban;
}

const banNotice = (ban) => ({
  type: ban.banType,
  restrictions: ban.restrictions,
  reason: ban.reason,
  expiresAt: ban.expiresAt || null
});

function enforceRestrictionsOnUser(anonymousId, restrictions) {
  if (restrictions.includes('matchmaking')) removeFromQueue(anonymousId, 'restricted');
  if (restrictions.includes('calls')) endUserCall(anonymousId, 'restricted');
  if (restrictions.includes('transfers')) cancelUserTransfers(anonymousId, 'restricted');
  if (restrictions.includes('messaging') || restrictions.includes('session')) {
    const matchId = userMatch.get(anonymousId);
    if (matchId) endMatch(matchId, anonymousId, 'restricted').catch(() => {});
  }
}

function applyBanToConnected(ban) {
  const handled = new Set();
  for (const socket of io.sockets.sockets.values()) {
    const ctx = socket.data.ctx;
    if (!ctx || !banMatchesCtx(ban, ctx)) continue;
    socket.emit('moderation:notice', banNotice(ban));
    if (!handled.has(ctx.anonymousId)) {
      handled.add(ctx.anonymousId);
      enforceRestrictionsOnUser(ctx.anonymousId, ban.restrictions);
    }
    if (ban.restrictions.includes('session')) socket.disconnect(true);
  }
}

const invalidateSession = (tokenHash) => sessionCache.delete(tokenHash);

async function issueSession(identity, deviceHash, ipHash) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(NOW() + config.sessionTtlMs);
  await UserSession.create({
    tokenHash: tokenHashOf(token),
    anonymousId: identity.anonymousId,
    identityHash: identity.identityHash,
    deviceHash: deviceHash || null,
    ipHash,
    expiresAt
  });
  await AnonymousIdentity.updateOne({ anonymousId: identity.anonymousId }, {
    $set: { lastSeenAt: new Date(), expiresAt: new Date(NOW() + config.sessionTtlMs + config.identityRetentionMs) }
  });
  return { token, expiresAt };
}

async function touchDevice(deviceHash, anonymousId) {
  if (!deviceHash) return;
  const update = {
    $setOnInsert: { createdAt: new Date(), violationCount: 0 },
    $set: { lastSeenAt: new Date(), expiresAt: new Date(NOW() + 15552000000) },
    $inc: { sessionCount: 1 },
    $push: { anonymousIds: { $each: [anonymousId], $slice: -10 } }
  };
  try {
    await DeviceIdentity.updateOne({ deviceHash }, update, { upsert: true });
  } catch (err) {
    if (err.code !== 11000) throw err;
    await DeviceIdentity.updateOne({ deviceHash }, update);
  }
}

const currentKeyOf = (identity) => {
  const key = (identity.keys || []).find((item) => item.version === identity.currentKeyVersion);
  return key ? { version: key.version, publicKey: key.publicKey, algorithm: key.algorithm } : null;
};

const sessionPayload = (identity, token, expiresAt) => ({
  sessionToken: token,
  anonymousId: identity.anonymousId,
  displayName: identity.displayName,
  expiresAt: expiresAt.toISOString(),
  keyVersion: identity.currentKeyVersion,
  limits: { fileTransferLimit: config.transferLimit, maxCiphertextLength: config.maxCiphertext }
});

function buildIceServers() {
  const servers = [];
  if (config.stunServers.length) servers.push({ urls: config.stunServers });
  if (config.turnServers.length) {
    const entry = { urls: config.turnServers };
    if (config.turnUsername) entry.username = config.turnUsername;
    if (config.turnPassword) entry.credential = config.turnPassword;
    servers.push(entry);
  }
  return servers;
}

async function loadIdentitySummaries(ids) {
  if (!ids.length) return new Map();
  const docs = await AnonymousIdentity.find({ anonymousId: { $in: ids } }).select('anonymousId displayName currentKeyVersion keys').lean();
  return new Map(docs.map((doc) => [doc.anonymousId, doc]));
}

function conversationLive(conversation) {
  if (!conversation.expiresAt) return true;
  if (conversation.expiresAt.getTime() > NOW()) return true;
  return !!conversation.matchId && activeMatches.has(conversation.matchId);
}

async function loadMembership(conversationId, anonymousId) {
  const [conversation, membership] = await Promise.all([
    Conversation.findOne({ conversationId }).lean(),
    ConversationMember.findOne({ conversationId, anonymousId }).lean()
  ]);
  if (!conversation || !membership || !conversationLive(conversation)) throw fail(404, 'not_found', 'Conversation not found');
  return { conversation, membership };
}

async function assertPeers(conversationId, actorId, peerId) {
  if (actorId === peerId) throw fail(400, 'invalid_payload', 'Cannot target yourself');
  const [conversation, members] = await Promise.all([
    Conversation.findOne({ conversationId }).lean(),
    ConversationMember.find({ conversationId, anonymousId: { $in: [actorId, peerId] } }).select('anonymousId').lean()
  ]);
  if (!conversation || members.length !== 2 || !conversationLive(conversation)) throw fail(404, 'not_found', 'Conversation or participant not found');
  if (await isBlockedBetween(actorId, peerId)) throw fail(403, 'blocked', 'Interaction is not permitted');
  return conversation;
}

async function assertRoomFeature(conversation, feature) {
  if (!conversation.roomId) return;
  const room = await Room.findOne({ roomId: conversation.roomId }).lean();
  if (!room) throw fail(404, 'not_found', 'Room not found');
  if (feature === 'calls' && !room.allowCalls) throw fail(403, 'calls_disabled', 'Calls are disabled in this room');
  if (feature === 'transfers' && !room.allowTransfers) throw fail(403, 'transfers_disabled', 'Transfers are disabled in this room');
  if (feature === 'voice' && !room.allowVoiceMessages) throw fail(403, 'voice_disabled', 'Voice messages are disabled in this room');
}

function serializeConversation(conversation, extra = {}) {
  return {
    id: conversation.conversationId,
    type: conversation.type,
    origin: conversation.origin,
    title: conversation.title || null,
    createdBy: conversation.createdBy,
    memberCount: conversation.memberCount,
    settings: conversation.settings || {},
    roomId: conversation.roomId || null,
    matchId: conversation.matchId || null,
    ephemeral: !!conversation.ephemeral,
    expiresAt: conversation.expiresAt || null,
    lastMessageAt: conversation.lastMessageAt || null,
    createdAt: conversation.createdAt,
    ...extra
  };
}

const serializeMember = (member, identities) => {
  const identity = identities.get(member.anonymousId);
  return {
    anonymousId: member.anonymousId,
    displayName: identity ? identity.displayName : null,
    keyVersion: identity ? identity.currentKeyVersion : null,
    role: member.role,
    joinedAt: member.joinedAt,
    lastReadAt: member.lastReadAt || null
  };
};

async function syncMemberCount(conversationId) {
  const count = await ConversationMember.countDocuments({ conversationId });
  await Conversation.updateOne({ conversationId }, { $set: { memberCount: count } });
  return count;
}

async function filterAddable(actorId, ids) {
  const added = [];
  const skipped = [];
  if (!ids.length) return { added, skipped };
  const [identities, blocks] = await Promise.all([
    AnonymousIdentity.find({ anonymousId: { $in: ids } }).select('anonymousId').lean(),
    Block.find({ $or: [{ blockerId: actorId, blockedId: { $in: ids } }, { blockerId: { $in: ids }, blockedId: actorId }] }).lean()
  ]);
  const known = new Set(identities.map((item) => item.anonymousId));
  const blocked = new Set(blocks.map((item) => (item.blockerId === actorId ? item.blockedId : item.blockerId)));
  for (const id of ids) {
    if (id === actorId) skipped.push({ anonymousId: id, reason: 'self' });
    else if (!known.has(id)) skipped.push({ anonymousId: id, reason: 'unknown' });
    else if (blocked.has(id)) skipped.push({ anonymousId: id, reason: 'blocked' });
    else added.push(id);
  }
  return { added, skipped };
}

async function notifyNewMembers(conversation, memberIds) {
  for (const id of memberIds) {
    joinConversationRooms(id, conversation.conversationId);
    emitToUser(id, 'conversation:created', serializeConversation(conversation));
  }
}

async function ensureDirectConversation(actorId, targetId) {
  const directKey = [actorId, targetId].sort().join('|');
  let conversation = await Conversation.findOne({ directKey }).lean();
  let created = false;
  if (!conversation) {
    try {
      const doc = await Conversation.create({
        conversationId: randomId('cv'),
        type: 'direct',
        origin: 'direct',
        createdBy: actorId,
        directKey,
        memberCount: 0
      });
      conversation = doc.toObject();
      created = true;
    } catch (err) {
      if (err.code !== 11000) throw err;
      conversation = await Conversation.findOne({ directKey }).lean();
    }
  }
  const ops = [actorId, targetId].map((anonymousId) => ({
    updateOne: {
      filter: { conversationId: conversation.conversationId, anonymousId },
      update: { $setOnInsert: { role: 'member', joinedAt: new Date() } },
      upsert: true
    }
  }));
  await ConversationMember.bulkWrite(ops, { ordered: false });
  conversation.memberCount = await syncMemberCount(conversation.conversationId);
  joinConversationRooms(actorId, conversation.conversationId);
  if (created) await notifyNewMembers(conversation, [targetId]);
  else joinConversationRooms(targetId, conversation.conversationId);
  return { conversation, created };
}

function readGroupSettings(value) {
  if (value === undefined || value === null) return {};
  const source = asObject(value);
  const settings = {};
  const invites = readBool(source, 'allowMemberInvites', undefined);
  const adminsOnly = readBool(source, 'onlyAdminsCanMessage', undefined);
  if (invites !== undefined) settings.allowMemberInvites = invites;
  if (adminsOnly !== undefined) settings.onlyAdminsCanMessage = adminsOnly;
  return settings;
}

async function createGroupConversation(actorId, body) {
  const title = readString(body, 'title', { min: 1, max: 60 });
  const memberIds = readIdArray(body, 'memberIds', { optional: true, max: config.maxGroupMembers - 1 }) || [];
  const settings = readGroupSettings(body.settings);
  const { added, skipped } = await filterAddable(actorId, memberIds);
  const conversationId = randomId('cv');
  const now = new Date();
  const doc = await Conversation.create({
    conversationId,
    type: 'group',
    origin: 'group',
    title: sanitizeDisplayName(title),
    createdBy: actorId,
    memberCount: added.length + 1,
    settings,
    lastMessageAt: null,
    activityAt: now
  });
  await ConversationMember.insertMany(
    [{ conversationId, anonymousId: actorId, role: 'owner', joinedAt: now }].concat(added.map((anonymousId) => ({ conversationId, anonymousId, role: 'member', joinedAt: now }))),
    { ordered: false }
  );
  const conversation = doc.toObject();
  joinConversationRooms(actorId, conversationId);
  await notifyNewMembers(conversation, added);
  return { conversation, skipped };
}

async function promoteSuccessor(conversation) {
  const members = await ConversationMember.find({ conversationId: conversation.conversationId }).lean();
  if (!members.length) return;
  members.sort((a, b) => ROLE_RANK[b.role] - ROLE_RANK[a.role] || a.joinedAt - b.joinedAt);
  const next = members[0];
  await ConversationMember.updateOne({ conversationId: conversation.conversationId, anonymousId: next.anonymousId }, { $set: { role: 'owner' } });
  if (conversation.roomId) await Room.updateOne({ roomId: conversation.roomId }, { $set: { ownerId: next.anonymousId } });
  emitToConversation(conversation.conversationId, 'conversation:role_changed', { conversationId: conversation.conversationId, anonymousId: next.anonymousId, role: 'owner' });
}

async function removeMemberFromConversation(conversation, targetId, byId) {
  const removed = await ConversationMember.findOneAndDelete({ conversationId: conversation.conversationId, anonymousId: targetId }).lean();
  if (!removed) return false;
  if (conversation.roomId) {
    const gone = await RoomMember.deleteOne({ roomId: conversation.roomId, anonymousId: targetId });
    if (gone.deletedCount) await Room.updateOne({ roomId: conversation.roomId, memberCount: { $gt: 0 } }, { $inc: { memberCount: -1 } });
  }
  const remaining = await syncMemberCount(conversation.conversationId);
  emitToConversation(conversation.conversationId, 'conversation:member_removed', { conversationId: conversation.conversationId, anonymousId: targetId, removedBy: byId });
  leaveConversationRooms(targetId, conversation.conversationId);
  if (remaining === 0) {
    await purgeConversation(conversation.conversationId);
    return true;
  }
  if (removed.role === 'owner' && conversation.type === 'group') await promoteSuccessor(conversation);
  return true;
}

async function purgeConversation(conversationId) {
  abortConversationActivity(conversationId, 'conversation_closed');
  const conversation = await Conversation.findOne({ conversationId }).lean();
  await Promise.all([
    Message.deleteMany({ conversationId }),
    MessageReaction.deleteMany({ conversationId }),
    ConversationMember.deleteMany({ conversationId }),
    TransferQuota.deleteMany({ conversationId })
  ]);
  if (conversation && conversation.roomId) {
    await Promise.all([Room.deleteOne({ roomId: conversation.roomId }), RoomMember.deleteMany({ roomId: conversation.roomId })]);
  }
  await Conversation.deleteOne({ conversationId });
  io.in(`conv:${conversationId}`).socketsLeave(`conv:${conversationId}`);
}

async function addMembers(actorId, conversationId, ids) {
  const { conversation, membership } = await loadMembership(conversationId, actorId);
  if (conversation.type !== 'group') throw fail(400, 'not_group', 'Members can only be added to group conversations');
  if (conversation.roomId) throw fail(400, 'room_managed', 'Room membership is managed through the room join flow');
  const allowed = ROLE_RANK[membership.role] >= ROLE_RANK.moderator || (conversation.settings && conversation.settings.allowMemberInvites);
  if (!allowed) throw fail(403, 'forbidden', 'You cannot add members');
  const existing = await ConversationMember.find({ conversationId, anonymousId: { $in: ids } }).select('anonymousId').lean();
  const existingSet = new Set(existing.map((item) => item.anonymousId));
  const candidates = ids.filter((id) => !existingSet.has(id));
  const { added, skipped } = await filterAddable(actorId, candidates);
  existingSet.forEach((id) => skipped.push({ anonymousId: id, reason: 'already_member' }));
  if (!added.length) return { added, skipped };
  const reserved = await Conversation.findOneAndUpdate(
    { conversationId, memberCount: { $lte: config.maxGroupMembers - added.length } },
    { $inc: { memberCount: added.length } },
    { returnDocument: 'after' }
  ).lean();
  if (!reserved) throw fail(409, 'group_full', 'The group is full');
  const now = new Date();
  try {
    await ConversationMember.insertMany(added.map((anonymousId) => ({ conversationId, anonymousId, role: 'member', joinedAt: now })), { ordered: false });
  } catch (err) {
    if (err.code !== 11000 && !err.writeErrors) throw err;
  }
  const count = await syncMemberCount(conversationId);
  reserved.memberCount = count;
  const identities = await loadIdentitySummaries(added);
  await notifyNewMembers(reserved, added);
  emitToConversation(conversationId, 'conversation:member_added', {
    conversationId,
    addedBy: actorId,
    members: added.map((anonymousId) => ({ anonymousId, displayName: identities.get(anonymousId) ? identities.get(anonymousId).displayName : null }))
  });
  return { added, skipped };
}

async function changeMemberRole(actorId, conversationId, targetId, role) {
  const { conversation, membership } = await loadMembership(conversationId, actorId);
  if (conversation.type !== 'group') throw fail(400, 'not_group', 'Roles only exist in group conversations');
  const target = await ConversationMember.findOne({ conversationId, anonymousId: targetId }).lean();
  if (!target) throw fail(404, 'not_found', 'Member not found');
  const actorRank = ROLE_RANK[membership.role];
  if (role === 'owner') {
    if (membership.role !== 'owner' || targetId === actorId) throw fail(403, 'forbidden', 'Only the owner can transfer ownership');
    await ConversationMember.updateOne({ conversationId, anonymousId: actorId }, { $set: { role: 'admin' } });
    await ConversationMember.updateOne({ conversationId, anonymousId: targetId }, { $set: { role: 'owner' } });
    if (conversation.roomId) await Room.updateOne({ roomId: conversation.roomId }, { $set: { ownerId: targetId } });
    emitToConversation(conversationId, 'conversation:role_changed', { conversationId, anonymousId: actorId, role: 'admin' });
    emitToConversation(conversationId, 'conversation:role_changed', { conversationId, anonymousId: targetId, role: 'owner' });
    return { anonymousId: targetId, role: 'owner' };
  }
  if (targetId === actorId) throw fail(403, 'forbidden', 'You cannot change your own role');
  if (actorRank < ROLE_RANK.admin) throw fail(403, 'forbidden', 'Only admins and the owner can change roles');
  if (ROLE_RANK[target.role] >= actorRank) throw fail(403, 'forbidden', 'You cannot change the role of this member');
  if (role === 'admin' && membership.role !== 'owner') throw fail(403, 'forbidden', 'Only the owner can grant admin');
  await ConversationMember.updateOne({ conversationId, anonymousId: targetId }, { $set: { role } });
  emitToConversation(conversationId, 'conversation:role_changed', { conversationId, anonymousId: targetId, role });
  return { anonymousId: targetId, role };
}

async function removeMember(actorId, conversationId, targetId) {
  const { conversation, membership } = await loadMembership(conversationId, actorId);
  if (targetId !== actorId) {
    if (conversation.type !== 'group') throw fail(403, 'forbidden', 'You can only remove yourself from a direct conversation');
    const target = await ConversationMember.findOne({ conversationId, anonymousId: targetId }).lean();
    if (!target) throw fail(404, 'not_found', 'Member not found');
    const actorRank = ROLE_RANK[membership.role];
    if (actorRank < ROLE_RANK.moderator || actorRank <= ROLE_RANK[target.role]) throw fail(403, 'forbidden', 'You cannot remove this member');
  }
  await removeMemberFromConversation(conversation, targetId, actorId);
  return { removed: true };
}

async function updateConversation(actorId, conversationId, body) {
  const { conversation, membership } = await loadMembership(conversationId, actorId);
  if (conversation.type !== 'group') throw fail(400, 'not_group', 'Only group settings can be changed');
  if (ROLE_RANK[membership.role] < ROLE_RANK.admin) throw fail(403, 'forbidden', 'Only admins and the owner can change settings');
  const update = {};
  const title = readString(body, 'title', { optional: true, min: 1, max: 60 });
  if (title !== undefined) update.title = sanitizeDisplayName(title);
  const settings = readGroupSettings(body.settings);
  for (const [key, value] of Object.entries(settings)) update[`settings.${key}`] = value;
  if (!Object.keys(update).length) throw fail(400, 'invalid_payload', 'Nothing to update');
  const updated = await Conversation.findOneAndUpdate({ conversationId }, { $set: update }, { returnDocument: 'after' }).lean();
  emitToConversation(conversationId, 'conversation:updated', serializeConversation(updated));
  return updated;
}

const encodeCursor = (message) => Buffer.from(`${message.createdAt.getTime()}:${message.messageId}`).toString('base64url');

function decodeCursor(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || value.length > 128) throw fail(400, 'invalid_cursor', 'Invalid cursor');
  const decoded = Buffer.from(value, 'base64url').toString('utf8');
  const match = /^(\d{10,15}):([A-Za-z0-9_-]{6,64})$/.exec(decoded);
  if (!match) throw fail(400, 'invalid_cursor', 'Invalid cursor');
  return { time: new Date(Number(match[1])), id: match[2] };
}

function serializeReaction(reaction) {
  return {
    reactionId: reaction.reactionId,
    messageId: reaction.messageId,
    senderId: reaction.anonymousId,
    ciphertext: reaction.ciphertext,
    nonce: reaction.nonce,
    keyVersion: reaction.keyVersion,
    createdAt: reaction.createdAt
  };
}

function serializeMessage(message, reactions) {
  const deleted = !!message.deletedAt;
  return {
    id: message.messageId,
    conversationId: message.conversationId,
    senderId: message.senderId,
    recipientId: message.recipientId || null,
    ciphertext: deleted ? null : message.ciphertext,
    nonce: deleted ? null : message.nonce,
    keyVersion: message.keyVersion,
    recipientKeyVersion: message.recipientKeyVersion || null,
    replyTo: message.replyTo || null,
    clientMessageId: message.clientMessageId || null,
    deleted,
    deletedAt: message.deletedAt || null,
    deliveredTo: (message.deliveredTo || []).map((item) => ({ anonymousId: item.anonymousId, at: item.at })),
    reactions: reactions || [],
    createdAt: message.createdAt
  };
}

async function createMessage(actor, conversationId, body) {
  checkRate('message', actor);
  await assertAllowed(actor, 'messaging');
  const { conversation, membership } = await loadMembership(conversationId, actor.anonymousId);
  if (conversation.settings && conversation.settings.onlyAdminsCanMessage && ROLE_RANK[membership.role] < ROLE_RANK.moderator) {
    throw fail(403, 'forbidden', 'Only moderators and above can post in this conversation');
  }
  const ciphertext = readString(body, 'ciphertext', { min: 1, max: config.maxCiphertext, pattern: BASE64_PATTERN });
  const nonce = readString(body, 'nonce', { min: 8, max: 128, pattern: BASE64_PATTERN });
  const keyVersion = readInt(body, 'keyVersion', { min: 1, max: 1000000 });
  const recipientKeyVersion = readInt(body, 'recipientKeyVersion', { optional: true, min: 1, max: 1000000, fallback: null });
  const clientMessageId = readId(body, 'clientMessageId', { optional: true });
  const replyTo = readId(body, 'replyTo', { optional: true }) || null;
  const requestedRecipient = readId(body, 'recipientId', { optional: true });
  let recipientId = null;
  if (conversation.type === 'direct') {
    const other = await ConversationMember.findOne({ conversationId, anonymousId: { $ne: actor.anonymousId } }).select('anonymousId').lean();
    if (!other) throw fail(409, 'peer_left', 'The other participant left this conversation');
    recipientId = other.anonymousId;
    if (requestedRecipient && requestedRecipient !== recipientId) throw fail(400, 'recipient_mismatch', 'recipientId does not match the conversation');
    if (await isBlockedBetween(actor.anonymousId, recipientId)) throw fail(403, 'blocked', 'Interaction is not permitted');
  } else if (requestedRecipient) {
    const target = await ConversationMember.exists({ conversationId, anonymousId: requestedRecipient });
    if (!target) throw fail(400, 'recipient_mismatch', 'recipientId is not a member');
    recipientId = requestedRecipient;
  }
  const now = new Date();
  let doc;
  try {
    doc = await Message.create({
      messageId: randomId('msg'),
      conversationId,
      senderId: actor.anonymousId,
      recipientId,
      ciphertext,
      nonce,
      keyVersion,
      recipientKeyVersion,
      clientMessageId,
      replyTo,
      createdAt: now,
      expiresAt: new Date(NOW() + config.messageRetentionMs)
    });
  } catch (err) {
    if (err.code === 11000 && clientMessageId) {
      const existing = await Message.findOne({ conversationId, senderId: actor.anonymousId, clientMessageId }).lean();
      if (existing) return { message: serializeMessage(existing), duplicate: true };
    }
    throw err;
  }
  Conversation.updateOne({ conversationId }, { $set: { lastMessageAt: now, activityAt: now } }).catch(() => {});
  const message = serializeMessage(doc.toObject());
  emitToConversation(conversationId, 'message:new', message);
  return { message, duplicate: false };
}

async function listMessages(actorId, conversationId, query) {
  await loadMembership(conversationId, actorId);
  const limit = clampQueryInt(query.limit, 1, 100, 50);
  const before = decodeCursor(query.before);
  const after = decodeCursor(query.after);
  if (before && after) throw fail(400, 'invalid_cursor', 'Use either before or after');
  const filter = { conversationId };
  if (before) filter.$or = [{ createdAt: { $lt: before.time } }, { createdAt: before.time, messageId: { $lt: before.id } }];
  if (after) filter.$or = [{ createdAt: { $gt: after.time } }, { createdAt: after.time, messageId: { $gt: after.id } }];
  const direction = after ? 1 : -1;
  let docs = await Message.find(filter).sort({ createdAt: direction, messageId: direction }).limit(limit + 1).lean();
  const hasMore = docs.length > limit;
  docs = docs.slice(0, limit);
  if (after) docs.reverse();
  const reactions = docs.length ? await MessageReaction.find({ messageId: { $in: docs.map((doc) => doc.messageId) } }).lean() : [];
  const grouped = new Map();
  for (const reaction of reactions) {
    if (!grouped.has(reaction.messageId)) grouped.set(reaction.messageId, []);
    grouped.get(reaction.messageId).push(serializeReaction(reaction));
  }
  const messages = docs.map((doc) => serializeMessage(doc, grouped.get(doc.messageId)));
  return {
    messages,
    hasMore,
    nextCursor: docs.length ? (after ? encodeCursor(docs[0]) : encodeCursor(docs[docs.length - 1])) : null,
    cursors: {
      older: docs.length ? encodeCursor(docs[docs.length - 1]) : null,
      newer: docs.length ? encodeCursor(docs[0]) : null
    }
  };
}

async function deleteMessage(actorId, messageId) {
  const message = await Message.findOne({ messageId }).lean();
  if (!message) throw fail(404, 'not_found', 'Message not found');
  const { membership } = await loadMembership(message.conversationId, actorId);
  if (message.deletedAt) return { messageId, conversationId: message.conversationId, deleted: true };
  if (message.senderId !== actorId) {
    const sender = await ConversationMember.findOne({ conversationId: message.conversationId, anonymousId: message.senderId }).lean();
    const senderRank = sender ? ROLE_RANK[sender.role] : 0;
    const actorRank = ROLE_RANK[membership.role];
    if (actorRank < ROLE_RANK.moderator || actorRank <= senderRank) throw fail(403, 'forbidden', 'You cannot delete this message');
  }
  const deletedAt = new Date();
  await Message.updateOne({ messageId }, { $set: { deletedAt, deletedBy: actorId, ciphertext: '-', nonce: '-' } });
  await MessageReaction.deleteMany({ messageId });
  const payload = { messageId, conversationId: message.conversationId, deletedBy: actorId, deletedAt };
  emitToConversation(message.conversationId, 'message:deleted', payload);
  return { ...payload, deleted: true };
}

async function setReaction(actor, messageId, body) {
  checkRate('message', actor, 'reaction');
  await assertAllowed(actor, 'messaging');
  const action = readEnum(body, 'action', ['add', 'remove']);
  const reactionId = readId(body, 'reactionId');
  const message = await Message.findOne({ messageId }).lean();
  if (!message || message.deletedAt) throw fail(404, 'not_found', 'Message not found');
  const { conversation } = await loadMembership(message.conversationId, actor.anonymousId);
  if (conversation.type === 'direct' && (await isBlockedBetween(actor.anonymousId, message.senderId === actor.anonymousId ? message.recipientId : message.senderId))) {
    throw fail(403, 'blocked', 'Interaction is not permitted');
  }
  const key = { messageId, anonymousId: actor.anonymousId, reactionId };
  let payload;
  if (action === 'add') {
    const ciphertext = readString(body, 'ciphertext', { min: 1, max: 2048, pattern: BASE64_PATTERN });
    const nonce = readString(body, 'nonce', { min: 8, max: 128, pattern: BASE64_PATTERN });
    const keyVersion = readInt(body, 'keyVersion', { min: 1, max: 1000000 });
    const exists = await MessageReaction.exists(key);
    if (!exists && (await MessageReaction.countDocuments({ messageId, anonymousId: actor.anonymousId })) >= 8) {
      throw fail(409, 'reaction_limit', 'Too many reactions on this message');
    }
    const doc = await MessageReaction.findOneAndUpdate(
      key,
      { $set: { ciphertext, nonce, keyVersion }, $setOnInsert: { conversationId: message.conversationId, createdAt: new Date(), expiresAt: message.expiresAt } },
      { upsert: true, returnDocument: 'after' }
    ).lean();
    payload = { action, conversationId: message.conversationId, ...serializeReaction(doc) };
  } else {
    await MessageReaction.deleteOne(key);
    payload = { action, conversationId: message.conversationId, messageId, reactionId, senderId: actor.anonymousId };
  }
  emitToConversation(message.conversationId, 'message:reaction', payload);
  const all = await MessageReaction.find({ messageId }).lean();
  return { reaction: payload, reactions: all.map(serializeReaction) };
}

async function markDelivered(actor, body) {
  const conversationId = readId(body, 'conversationId');
  const single = readId(body, 'messageId', { optional: true });
  const list = readIdArray(body, 'messageIds', { optional: true, max: 100 });
  const ids = list || (single ? [single] : null);
  if (!ids || !ids.length) throw fail(400, 'invalid_payload', 'messageId or messageIds is required');
  await loadMembership(conversationId, actor.anonymousId);
  const at = new Date();
  await Message.updateMany(
    { conversationId, messageId: { $in: ids }, senderId: { $ne: actor.anonymousId }, 'deliveredTo.anonymousId': { $ne: actor.anonymousId } },
    { $push: { deliveredTo: { $each: [{ anonymousId: actor.anonymousId, at }], $slice: -200 } } }
  );
  emitToConversation(conversationId, 'message:delivered', { conversationId, messageIds: ids, deliveredTo: actor.anonymousId, at });
  return { delivered: ids.length };
}

async function markRead(actor, body) {
  const conversationId = readId(body, 'conversationId');
  const messageId = readId(body, 'messageId');
  await loadMembership(conversationId, actor.anonymousId);
  const message = await Message.findOne({ conversationId, messageId }).select('createdAt').lean();
  if (!message) throw fail(404, 'not_found', 'Message not found');
  await ConversationMember.updateOne(
    { conversationId, anonymousId: actor.anonymousId, $or: [{ lastReadAt: null }, { lastReadAt: { $lt: message.createdAt } }] },
    { $set: { lastReadAt: message.createdAt, lastReadMessageId: messageId } }
  );
  const at = new Date();
  emitToConversation(conversationId, 'message:read', { conversationId, messageId, readerId: actor.anonymousId, at });
  return { read: true };
}

function serializeRoom(room, extra = {}) {
  return {
    id: room.roomId,
    name: room.name || null,
    ownerId: room.ownerId,
    maxMembers: room.maxMembers,
    memberCount: room.memberCount,
    hasPin: !!room.pinHash,
    expiresAt: room.expiresAt,
    allowCalls: room.allowCalls,
    allowTransfers: room.allowTransfers,
    allowVoiceMessages: room.allowVoiceMessages,
    createdAt: room.createdAt,
    ...extra
  };
}

async function hashPin(pin, salt) {
  const derived = await scrypt(pin, salt, 32);
  return derived.toString('hex');
}

async function createRoom(actor, body) {
  checkRate('roomCreate', actor);
  await assertAllowed(actor, 'rooms');
  const input = { ...(isPlainObject(body.settings) ? body.settings : {}), ...body };
  const name = readString(input, 'name', { optional: true, min: 1, max: 48 });
  const maxMembers = readInt(input, 'maxMembers', { optional: true, min: 2, max: config.maxRoomMembers, fallback: Math.min(20, config.maxRoomMembers) });
  const pin = readString(input, 'pin', { optional: true, min: 4, max: 12, pattern: /^[A-Za-z0-9]+$/ });
  let expiresAtMs;
  if (input.expiresAt !== undefined && input.expiresAt !== null) {
    expiresAtMs = typeof input.expiresAt === 'string' ? Date.parse(input.expiresAt) : NaN;
    if (!Number.isFinite(expiresAtMs)) throw fail(400, 'invalid_payload', 'expiresAt is invalid');
  } else {
    const seconds = readInt(input, 'expiresInSeconds', { optional: true, min: 60, max: Math.floor(config.roomMaxLifetimeMs / 1000), fallback: 3600 });
    expiresAtMs = NOW() + seconds * 1000;
  }
  if (expiresAtMs < NOW() + 60000 || expiresAtMs > NOW() + config.roomMaxLifetimeMs) throw fail(400, 'invalid_expiry', 'Room expiry is outside the permitted range');
  const allowCalls = readBool(input, 'allowCalls', true);
  const allowTransfers = readBool(input, 'allowTransfers', true);
  const allowVoiceMessages = readBool(input, 'allowVoiceMessages', true);
  const active = await Room.countDocuments({ ownerId: actor.anonymousId, expiresAt: { $gt: new Date() } });
  if (active >= config.roomsPerIdentity) throw fail(409, 'room_limit', 'Too many active rooms');
  let pinSalt = null;
  let pinHash = null;
  if (pin) {
    pinSalt = crypto.randomBytes(16).toString('hex');
    pinHash = await hashPin(pin, pinSalt);
  }
  const roomId = randomId('rm', 9);
  const conversationId = randomId('cv');
  const now = new Date();
  const expiresAt = new Date(expiresAtMs);
  const displayName = name ? sanitizeDisplayName(name) : null;
  await Conversation.create({
    conversationId,
    type: 'group',
    origin: 'room',
    title: displayName,
    createdBy: actor.anonymousId,
    roomId,
    memberCount: 1,
    settings: { allowMemberInvites: false, onlyAdminsCanMessage: false },
    expiresAt
  });
  await ConversationMember.create({ conversationId, anonymousId: actor.anonymousId, role: 'owner', joinedAt: now });
  const room = await Room.create({
    roomId,
    ownerId: actor.anonymousId,
    name: displayName,
    pinHash,
    pinSalt,
    maxMembers,
    memberCount: 1,
    allowCalls,
    allowTransfers,
    allowVoiceMessages,
    conversationId,
    expiresAt
  });
  await RoomMember.create({ roomId, anonymousId: actor.anonymousId, joinedAt: now, expiresAt });
  joinConversationRooms(actor.anonymousId, conversationId);
  return serializeRoom(room.toObject(), { conversationId });
}

function assertPinAttemptsAllowed(keys) {
  const now = NOW();
  for (const key of keys) {
    const entry = pinAttempts.get(key);
    if (entry && entry.lockedUntil > now) throw fail(429, 'pin_locked', 'Too many incorrect PIN attempts', { retryAfterMs: entry.lockedUntil - now });
  }
}

function recordPinFailure(keys) {
  const now = NOW();
  for (const key of keys) {
    const entry = pinAttempts.get(key) || { count: 0, lockedUntil: 0, touchedAt: now };
    entry.count += 1;
    entry.touchedAt = now;
    if (entry.count >= 5) {
      entry.lockedUntil = now + 600000;
      entry.count = 0;
    }
    pinAttempts.set(key, entry);
  }
}

async function joinRoom(actor, roomId, body) {
  checkRate('roomJoin', actor);
  await assertAllowed(actor, 'rooms');
  const room = await Room.findOne({ roomId, expiresAt: { $gt: new Date() } }).lean();
  if (!room) throw fail(404, 'not_found', 'Room not found');
  const already = await RoomMember.exists({ roomId, anonymousId: actor.anonymousId });
  if (already) return serializeRoom(room, { conversationId: room.conversationId });
  if (room.ownerId !== actor.anonymousId && (await isBlockedBetween(room.ownerId, actor.anonymousId))) throw fail(403, 'forbidden', 'You cannot join this room');
  if (room.pinHash) {
    const keys = [`${roomId}:${actor.anonymousId}`, `${roomId}:${actor.ipHash}`];
    assertPinAttemptsAllowed(keys);
    const pin = readString(body, 'pin', { min: 4, max: 12, pattern: /^[A-Za-z0-9]+$/ });
    const candidate = Buffer.from(await hashPin(pin, room.pinSalt), 'hex');
    if (!crypto.timingSafeEqual(candidate, Buffer.from(room.pinHash, 'hex'))) {
      recordPinFailure(keys);
      throw fail(403, 'invalid_pin', 'Incorrect PIN');
    }
  }
  const reserved = await Room.findOneAndUpdate(
    { roomId, expiresAt: { $gt: new Date() }, memberCount: { $lt: room.maxMembers } },
    { $inc: { memberCount: 1 } },
    { returnDocument: 'after' }
  ).lean();
  if (!reserved) throw fail(409, 'room_full', 'The room is full');
  try {
    await RoomMember.create({ roomId, anonymousId: actor.anonymousId, joinedAt: new Date(), expiresAt: room.expiresAt });
  } catch (err) {
    await Room.updateOne({ roomId }, { $inc: { memberCount: -1 } });
    if (err.code === 11000) return serializeRoom(room, { conversationId: room.conversationId });
    throw err;
  }
  await ConversationMember.updateOne(
    { conversationId: room.conversationId, anonymousId: actor.anonymousId },
    { $setOnInsert: { role: 'member', joinedAt: new Date() } },
    { upsert: true }
  );
  await syncMemberCount(room.conversationId);
  joinConversationRooms(actor.anonymousId, room.conversationId);
  const identity = await AnonymousIdentity.findOne({ anonymousId: actor.anonymousId }).select('displayName').lean();
  emitToConversation(room.conversationId, 'room:member_joined', {
    roomId,
    conversationId: room.conversationId,
    anonymousId: actor.anonymousId,
    displayName: identity ? identity.displayName : null
  });
  return serializeRoom(reserved, { conversationId: room.conversationId });
}

async function leaveRoom(actor, roomId) {
  const room = await Room.findOne({ roomId }).lean();
  if (!room) throw fail(404, 'not_found', 'Room not found');
  const conversation = await Conversation.findOne({ conversationId: room.conversationId }).lean();
  if (!conversation) throw fail(404, 'not_found', 'Room not found');
  const removed = await removeMemberFromConversation(conversation, actor.anonymousId, actor.anonymousId);
  if (!removed) throw fail(404, 'not_found', 'You are not a member of this room');
  return { left: true };
}

async function closeRoom(actor, roomId) {
  const room = await Room.findOne({ roomId }).lean();
  if (!room) throw fail(404, 'not_found', 'Room not found');
  if (room.ownerId !== actor.anonymousId) throw fail(403, 'forbidden', 'Only the owner can close the room');
  emitToConversation(room.conversationId, 'room:closed', { roomId, conversationId: room.conversationId });
  await purgeConversation(room.conversationId);
  await Promise.all([Room.deleteOne({ roomId }), RoomMember.deleteMany({ roomId })]);
  return { closed: true };
}

async function blockUser(actor, body) {
  checkRate('block', actor);
  const targetId = readId(body, 'anonymousId');
  if (targetId === actor.anonymousId) throw fail(400, 'invalid_payload', 'You cannot block yourself');
  const target = await AnonymousIdentity.exists({ anonymousId: targetId });
  if (!target) throw fail(404, 'not_found', 'Identity not found');
  try {
    await Block.create({ blockerId: actor.anonymousId, blockedId: targetId });
  } catch (err) {
    if (err.code !== 11000) throw err;
  }
  for (const entry of [waitingEntry(actor.anonymousId), waitingEntry(targetId)]) {
    if (entry) {
      entry.blocked.add(entry.anonymousId === actor.anonymousId ? targetId : actor.anonymousId);
    }
  }
  const matchId = userMatch.get(actor.anonymousId);
  const state = matchId && activeMatches.get(matchId);
  if (state && state.participants.includes(targetId)) await endMatch(matchId, actor.anonymousId, 'blocked');
  const callId = userCall.get(actor.anonymousId);
  const call = callId && activeCalls.get(callId);
  if (call && (call.callerId === targetId || call.receiverId === targetId)) endCall(call, { by: actor.anonymousId, reason: 'blocked' });
  for (const transfer of [...transfers.values()]) {
    const pair = [transfer.senderId, transfer.receiverId];
    if (pair.includes(actor.anonymousId) && pair.includes(targetId)) cancelTransfer(transfer, actor.anonymousId, 'blocked');
  }
  return { blocked: true, anonymousId: targetId };
}

async function unblockUser(actor, targetId) {
  const result = await Block.deleteOne({ blockerId: actor.anonymousId, blockedId: targetId });
  const entry = waitingEntry(actor.anonymousId);
  if (entry) entry.blocked.delete(targetId);
  const other = waitingEntry(targetId);
  if (other) other.blocked.delete(actor.anonymousId);
  return { unblocked: result.deletedCount > 0 };
}

async function sharesConversation(a, b) {
  const mine = await ConversationMember.find({ anonymousId: a }).select('conversationId').limit(500).lean();
  if (!mine.length) return false;
  const found = await ConversationMember.exists({ anonymousId: b, conversationId: { $in: mine.map((item) => item.conversationId) } });
  return !!found;
}

async function createReport(actor, body) {
  checkRate('report', actor);
  const reportedId = readId(body, 'reportedId');
  const category = readEnum(body, 'category', REPORT_CATEGORIES);
  const description = readString(body, 'description', { optional: true, min: 1, max: 500, multiline: true }) || null;
  const conversationId = readId(body, 'conversationId', { optional: true }) || null;
  if (reportedId === actor.anonymousId) throw fail(400, 'invalid_payload', 'You cannot report yourself');
  if (conversationId) {
    const members = await ConversationMember.countDocuments({ conversationId, anonymousId: { $in: [actor.anonymousId, reportedId] } });
    if (members !== 2) throw fail(403, 'no_shared_context', 'You can only report participants you have interacted with');
  } else if (!(await sharesConversation(actor.anonymousId, reportedId))) {
    throw fail(403, 'no_shared_context', 'You can only report participants you have interacted with');
  }
  const reporterHash = actor.identityHash;
  const reportedHash = identityHashOf(reportedId);
  const since = new Date(NOW() - 86400000);
  const duplicate = await Report.findOne({ reporterHash, reportedHash, category, createdAt: { $gt: since } }).select('reportId').lean();
  if (duplicate) return { reportId: duplicate.reportId, status: 'open', duplicate: true };
  const report = await Report.create({
    reportId: randomId('rp', 9),
    reporterHash,
    reportedHash,
    category,
    conversationId,
    description,
    expiresAt: new Date(NOW() + 7776000000)
  });
  const reporters = await Report.distinct('reporterHash', { reportedHash, category: { $ne: 'other' }, createdAt: { $gt: since } });
  if (reporters.length >= config.reportRestrictThreshold) {
    const existing = await Ban.exists({ anonymousIdentityHash: reportedHash, source: 'reports', status: 'active' });
    if (!existing) {
      const ban = await createBan({
        scope: 'identity',
        identityHash: reportedHash,
        banType: 'temporary',
        restrictions: ['matchmaking', 'rooms'],
        reason: 'multiple_reports',
        source: 'reports',
        durationMs: config.tempBanMs
      });
      applyBanToConnected(ban);
    }
  }
  return { reportId: report.reportId, status: 'open', duplicate: false };
}

function findKnownTransfer(transferId) {
  const active = transfers.get(transferId);
  if (active) return { senderId: active.senderId, receiverId: active.receiverId, conversationId: active.conversationId, status: active.status };
  const recent = recentTransfers.get(transferId);
  return recent || null;
}

async function applyViolation(offenderId, offenderHash, event) {
  const latest = await UserSession.findOne({ anonymousId: offenderId }).sort({ createdAt: -1 }).select('deviceHash').lean();
  const deviceHash = latest ? latest.deviceHash : null;
  const identity = await AnonymousIdentity.findOneAndUpdate({ anonymousId: offenderId }, { $inc: { violationCount: 1 } }, { returnDocument: 'after' }).select('violationCount').lean();
  let count = identity ? identity.violationCount : 1;
  if (deviceHash) {
    const device = await DeviceIdentity.findOneAndUpdate({ deviceHash }, { $inc: { violationCount: 1 } }, { returnDocument: 'after' }).select('violationCount').lean();
    if (device) count = Math.max(count, device.violationCount);
  }
  const punishment = punishmentFor(count);
  const base = {
    banType: punishment.banType,
    restrictions: punishment.restrictions,
    reason: 'nsfw_policy',
    violationCount: count,
    durationMs: punishment.durationMs
  };
  const identityBan = await createBan({ ...base, scope: 'identity', identityHash: offenderHash });
  if (punishment.banType !== 'warning' && deviceHash) await createBan({ ...base, scope: 'device', deviceHash });
  emitToUser(offenderId, 'moderation:notice', banNotice(identityBan));
  enforceRestrictionsOnUser(offenderId, punishment.restrictions);
  if (punishment.restrictions.includes('session')) {
    for (const socket of io.sockets.sockets.values()) {
      if (socket.data.ctx && socket.data.ctx.anonymousId === offenderId) socket.disconnect(true);
    }
  }
  return count;
}

async function recordModerationEvent(actor, body) {
  checkRate('moderation', actor);
  const type = readEnum(body, 'type', ['nsfw_detected', 'nsfw_blocked_locally']);
  const category = readEnum(body, 'category', ['explicit_nudity', 'sexual_activity', 'suggestive', 'other']);
  const confidence = readNumber(body, 'confidence', 0, 1);
  const transferId = readId(body, 'transferId');
  const conversationId = readId(body, 'conversationId');
  const transfer = findKnownTransfer(transferId);
  if (!transfer || transfer.conversationId !== conversationId) throw fail(404, 'unknown_transfer', 'Transfer not found');
  if (transfer.receiverId !== actor.anonymousId) throw fail(403, 'forbidden', 'Only the receiver of a transfer can report it');
  if (!['accepted', 'completed'].includes(transfer.status)) throw fail(409, 'invalid_state', 'Transfer was never accepted');
  const offenderHash = identityHashOf(transfer.senderId);
  const reporterHash = actor.identityHash;
  let action = 'recorded';
  if (type === 'nsfw_detected') {
    if (confidence < config.nsfw.reviewThreshold) action = 'ignored';
    else if (confidence < config.nsfw.blockThreshold) action = 'review';
    else action = 'confirmed';
  }
  const since = new Date(NOW() - 86400000);
  if (action === 'review') {
    const filter = { anonymousIdentityHash: offenderHash, action: 'review', createdAt: { $gt: since } };
    const [count, reporters] = await Promise.all([ModerationEvent.countDocuments(filter), ModerationEvent.distinct('reporterIdentityHash', filter)]);
    const distinct = new Set(reporters);
    distinct.add(reporterHash);
    if (count + 1 >= config.nsfw.reviewEscalation && distinct.size >= 2) action = 'confirmed';
  }
  if (action === 'confirmed') {
    const repeat = await ModerationEvent.exists({ anonymousIdentityHash: offenderHash, reporterIdentityHash: reporterHash, action: 'confirmed', createdAt: { $gt: since } });
    if (repeat) action = 'duplicate';
  }
  const eventId = randomId('mev', 9);
  try {
    await ModerationEvent.create({
      eventId,
      anonymousIdentityHash: offenderHash,
      reporterIdentityHash: reporterHash,
      conversationId,
      transferId,
      type,
      category,
      confidence,
      action,
      expiresAt: new Date(NOW() + 15552000000)
    });
  } catch (err) {
    if (err.code === 11000) throw fail(409, 'already_reported', 'This transfer was already reported');
    throw err;
  }
  let transferBlocked = action === 'confirmed' || action === 'review';
  if (action === 'confirmed') {
    const count = await applyViolation(transfer.senderId, offenderHash, { transferId });
    await ModerationEvent.updateOne({ eventId }, { $set: { violationCount: count } });
    transferBlocked = true;
  }
  return { eventId, action, transferBlocked };
}

const waitingEntry = (id) => {
  const mode = waitingIndex.get(id);
  return mode ? matchQueues[mode].get(id) || null : null;
};

function removeFromQueue(id, reason) {
  const mode = waitingIndex.get(id);
  if (!mode) return false;
  matchQueues[mode].delete(id);
  waitingIndex.delete(id);
  if (reason) emitToUser(id, 'match:left', { reason });
  return true;
}

function parseMatchPreferences(data) {
  const mode = readEnum(data, 'mode', MATCH_MODES, { optional: true }) || 'text';
  let interests = [];
  if (data.interests !== undefined && data.interests !== null) {
    if (!Array.isArray(data.interests) || data.interests.length > 10) throw fail(400, 'invalid_payload', 'interests is invalid');
    interests = [...new Set(data.interests.map((item) => {
      if (typeof item !== 'string') throw fail(400, 'invalid_payload', 'interests is invalid');
      const normalized = item.trim().toLowerCase();
      if (!INTEREST_PATTERN.test(normalized)) throw fail(400, 'invalid_payload', 'interests contains an invalid value');
      return normalized;
    }))];
  }
  let language = null;
  if (data.language !== undefined && data.language !== null && data.language !== '') {
    if (typeof data.language !== 'string' || !/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})?$/.test(data.language)) throw fail(400, 'invalid_payload', 'language is invalid');
    language = data.language.split('-')[0].toLowerCase();
  }
  return { mode, interests, language };
}

function matchStatus(id) {
  const matchId = userMatch.get(id);
  const state = matchId && activeMatches.get(matchId);
  if (state) {
    return {
      status: 'matched',
      match: {
        matchId,
        mode: state.mode,
        conversationId: state.conversationId,
        callId: state.callId,
        initiator: state.initiatorId === id,
        partnerId: state.participants.find((p) => p !== id),
        since: new Date(state.createdAt)
      }
    };
  }
  const entry = waitingEntry(id);
  if (entry) {
    const position = [...matchQueues[entry.mode].keys()].indexOf(id) + 1;
    return { status: 'waiting', queue: { mode: entry.mode, interests: entry.interests, language: entry.language, position, waitedMs: NOW() - entry.joinedAt } };
  }
  return { status: 'idle' };
}

async function joinMatchmaking(actor, prefs) {
  checkRate('matchmaking', actor);
  await assertAllowed(actor, 'matchmaking');
  const id = actor.anonymousId;
  if (!isOnline(id)) throw fail(409, 'socket_required', 'Connect to the realtime channel before joining matchmaking');
  if (userCall.has(id)) throw fail(409, 'busy', 'Finish your current call first');
  const currentMatch = userMatch.get(id);
  if (currentMatch) await endMatch(currentMatch, id, 'skipped');
  const previous = waitingEntry(id);
  if (previous && previous.mode === prefs.mode && previous.language === prefs.language && previous.interests.join('|') === prefs.interests.join('|')) return matchStatus(id);
  const blocked = await loadBlockedSet(id);
  const joinedAt = previous ? previous.joinedAt : NOW();
  removeFromQueue(id);
  if (matchQueues[prefs.mode].size >= config.maxQueueSize) throw fail(503, 'queue_full', 'Matchmaking is busy, try again shortly');
  matchQueues[prefs.mode].set(id, { anonymousId: id, mode: prefs.mode, interests: prefs.interests, language: prefs.language, blocked, joinedAt });
  waitingIndex.set(id, prefs.mode);
  scheduleMatcher();
  return matchStatus(id);
}

async function leaveMatchmaking(actor) {
  const id = actor.anonymousId;
  const matchId = userMatch.get(id);
  let left = false;
  if (matchId) left = await endMatch(matchId, id, 'left');
  if (removeFromQueue(id)) left = true;
  emitToUser(id, 'match:left', { reason: 'left' });
  return { left, status: 'idle' };
}

const pairKeyOf = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
const sharedInterests = (a, b) => {
  const set = new Set(a.interests);
  return b.interests.filter((item) => set.has(item));
};

function compatible(a, b, now) {
  if (a.blocked.has(b.anonymousId) || b.blocked.has(a.anonymousId)) return false;
  if (a.language && b.language && a.language !== b.language) return false;
  const until = recentPairs.get(pairKeyOf(a.anonymousId, b.anonymousId));
  if (until && until > now) return false;
  if (a.interests.length && b.interests.length && !sharedInterests(a, b).length) {
    if (Math.min(now - a.joinedAt, now - b.joinedAt) < TIMING.interestWaitMs) return false;
  }
  return true;
}

let matcherRunning = false;
let matcherDirty = false;

function scheduleMatcher() {
  matcherDirty = true;
  if (matcherRunning) return;
  matcherRunning = true;
  setImmediate(runMatcher);
}

async function runMatcher() {
  try {
    while (matcherDirty) {
      matcherDirty = false;
      for (const mode of MATCH_MODES) await pairQueue(mode);
    }
  } catch (err) {
    logError('matcher failure', err);
  } finally {
    matcherRunning = false;
  }
}

async function pairQueue(mode) {
  const queue = matchQueues[mode];
  const now = NOW();
  const entries = [...queue.values()]
    .filter((entry) => isOnline(entry.anonymousId) && (mode === 'text' || !userCall.has(entry.anonymousId)))
    .sort((a, b) => a.joinedAt - b.joinedAt)
    .slice(0, 500);
  const used = new Set();
  const pairs = [];
  for (const a of entries) {
    if (used.has(a.anonymousId)) continue;
    let best = null;
    let bestScore = -1;
    for (const b of entries) {
      if (b === a || used.has(b.anonymousId) || !compatible(a, b, now)) continue;
      const score = sharedInterests(a, b).length * 100000 + Math.min(now - a.joinedAt, now - b.joinedAt) / 1000;
      if (score > bestScore) {
        best = b;
        bestScore = score;
      }
    }
    if (best) {
      used.add(a.anonymousId);
      used.add(best.anonymousId);
      pairs.push([a, best]);
    }
  }
  for (const [a, b] of pairs) {
    queue.delete(a.anonymousId);
    queue.delete(b.anonymousId);
    waitingIndex.delete(a.anonymousId);
    waitingIndex.delete(b.anonymousId);
    await createMatch(a, b, mode);
  }
}

function requeue(entries) {
  for (const entry of entries) {
    if (!isOnline(entry.anonymousId) || userMatch.has(entry.anonymousId) || waitingIndex.has(entry.anonymousId)) continue;
    matchQueues[entry.mode].set(entry.anonymousId, entry);
    waitingIndex.set(entry.anonymousId, entry.mode);
  }
}

async function createMatch(a, b, mode) {
  const shared = sharedInterests(a, b);
  const participants = [a.anonymousId, b.anonymousId];
  const matchId = randomId('mt');
  const initiatorId = participants[crypto.randomInt(2)];
  const responderId = participants.find((id) => id !== initiatorId);
  const conversationId = randomId('cv');
  const callId = mode === 'video' ? randomId('call') : null;
  const state = { matchId, mode, participants, initiatorId, conversationId, callId, ended: false, endReason: null, createdAt: NOW() };
  activeMatches.set(matchId, state);
  participants.forEach((id) => userMatch.set(id, matchId));
  recentPairs.set(pairKeyOf(participants[0], participants[1]), NOW() + TIMING.rematchBlockMs);
  try {
    const now = new Date();
    await Conversation.create({
      conversationId,
      type: 'direct',
      origin: 'match',
      matchId,
      ephemeral: true,
      createdBy: initiatorId,
      memberCount: 2,
      expiresAt: new Date(NOW() + TIMING.matchConversationMs)
    });
    await ConversationMember.insertMany(participants.map((anonymousId) => ({ conversationId, anonymousId, role: 'member', joinedAt: now })));
    await Match.create({ matchId, mode, participants, initiatorId, conversationId, callId, sharedInterests: shared, expiresAt: new Date(NOW() + 86400000) });
    if (callId) {
      registerCall({ callId, conversationId, callerId: initiatorId, receiverId: responderId, type: 'video', status: 'active' });
      await CallSession.create({ callId, conversationId, callerId: initiatorId, receiverId: responderId, type: 'video', status: 'active', startedAt: now, answeredAt: now, expiresAt: new Date(NOW() + 2592000000) });
      log('call started', { call: shortId(callId), type: 'video', auto: 'match' });
    }
    const identities = await loadIdentitySummaries(participants);
    if (state.ended) {
      await persistMatchEnd(state, state.endReason || 'left');
      return;
    }
    participants.forEach((id) => joinConversationRooms(id, conversationId));
    for (const id of participants) {
      const partnerId = participants.find((p) => p !== id);
      const partner = identities.get(partnerId);
      emitToUser(id, 'match:found', {
        matchId,
        mode,
        conversationId,
        callId,
        initiator: initiatorId === id,
        sharedInterests: shared,
        language: a.language && b.language ? a.language : null,
        partner: {
          anonymousId: partnerId,
          displayName: partner ? partner.displayName : null,
          key: partner ? currentKeyOf(partner) : null
        },
        iceServers: mode === 'video' ? buildIceServers() : undefined
      });
    }
    log('match created', { match: shortId(matchId), mode, a: shortId(participants[0]), b: shortId(participants[1]) });
  } catch (err) {
    logError('match creation failed', err);
    if (!state.ended) {
      state.ended = true;
      activeMatches.delete(matchId);
      participants.forEach((id) => { if (userMatch.get(id) === matchId) userMatch.delete(id); });
      if (callId && activeCalls.has(callId)) unregisterCall(activeCalls.get(callId));
      Conversation.deleteOne({ conversationId }).catch(() => {});
      ConversationMember.deleteMany({ conversationId }).catch(() => {});
      Match.deleteOne({ matchId }).catch(() => {});
      participants.forEach((id) => emitToUser(id, 'match:error', { code: 'match_failed', message: 'Could not create the match, you were returned to the queue' }));
      requeue([a, b]);
    }
  }
}

async function persistMatchEnd(state, reason) {
  const now = new Date();
  await Promise.all([
    Match.updateOne({ matchId: state.matchId }, { $set: { status: 'ended', endReason: reason, endedAt: now, expiresAt: new Date(NOW() + 86400000) } }),
    Conversation.updateOne({ conversationId: state.conversationId, ephemeral: true }, { $set: { expiresAt: new Date(NOW() + TIMING.matchGraceMs) } })
  ]);
}

async function endMatch(matchId, byId, reason) {
  const state = activeMatches.get(matchId);
  if (!state || state.ended) return false;
  state.ended = true;
  state.endReason = reason;
  activeMatches.delete(matchId);
  state.participants.forEach((id) => { if (userMatch.get(id) === matchId) userMatch.delete(id); });
  if (state.callId && activeCalls.has(state.callId)) endCall(activeCalls.get(state.callId), { by: byId, reason: 'match_ended' });
  cancelConversationTransfers(state.conversationId, 'match_ended');
  const payload = { matchId, conversationId: state.conversationId, reason };
  state.participants.filter((id) => id !== byId).forEach((id) => emitToUser(id, 'match:ended', payload));
  persistMatchEnd(state, reason).catch((err) => logError('match persist failed', err));
  return true;
}

function sweepQueues() {
  const now = NOW();
  for (const mode of MATCH_MODES) {
    for (const [id, entry] of matchQueues[mode]) {
      if (now - entry.joinedAt > config.queueTimeoutMs) removeFromQueue(id, 'timeout');
      else if (!isOnline(id)) removeFromQueue(id);
    }
  }
  for (const [key, until] of recentPairs) {
    if (until <= now) recentPairs.delete(key);
  }
}

function registerCall(fields) {
  const call = { ...fields, startedAt: NOW(), answeredAt: fields.status === 'active' ? NOW() : null, sockets: {}, timer: null };
  activeCalls.set(call.callId, call);
  userCall.set(call.callerId, call.callId);
  userCall.set(call.receiverId, call.callId);
  if (call.status === 'ringing') call.timer = setTimeout(() => endCall(call, { by: null, reason: 'no_answer', status: 'missed' }), TIMING.callRingMs);
  return call;
}

function unregisterCall(call) {
  clearTimeout(call.timer);
  activeCalls.delete(call.callId);
  [call.callerId, call.receiverId].forEach((id) => { if (userCall.get(id) === call.callId) userCall.delete(id); });
}

function endCall(call, options = {}) {
  if (!activeCalls.has(call.callId)) return false;
  unregisterCall(call);
  const by = options.by || null;
  const status = options.status || (call.status === 'active' ? 'ended' : by === call.callerId ? 'cancelled' : 'ended');
  const payload = { callId: call.callId, conversationId: call.conversationId, reason: options.reason || 'hangup', endedBy: by };
  const targets = by === call.callerId ? [call.receiverId] : by === call.receiverId ? [call.callerId] : [call.callerId, call.receiverId];
  targets.forEach((id) => emitToUser(id, options.event || 'call:end', payload));
  CallSession.updateOne({ callId: call.callId }, { $set: { status, endedAt: new Date(), endReason: payload.reason } }).catch(() => {});
  log('call ended', { call: shortId(call.callId), status, reason: payload.reason });
  return true;
}

function endUserCall(anonymousId, reason) {
  const callId = userCall.get(anonymousId);
  const call = callId && activeCalls.get(callId);
  if (call) endCall(call, { by: anonymousId, reason });
}

function activateCall(call, socketId) {
  if (call.status !== 'ringing') return;
  clearTimeout(call.timer);
  call.status = 'active';
  call.answeredAt = NOW();
  call.sockets[call.receiverId] = socketId;
  CallSession.updateOne({ callId: call.callId }, { $set: { status: 'active', answeredAt: new Date() } }).catch(() => {});
  emitToUser(call.callerId, 'call:accept', { callId: call.callId, conversationId: call.conversationId, receiverId: call.receiverId });
  io.to(`user:${call.receiverId}`).except(socketId).emit('call:end', { callId: call.callId, conversationId: call.conversationId, reason: 'answered_elsewhere', endedBy: null });
  log('call started', { call: shortId(call.callId), type: call.type });
}

function emitToCallPeer(call, peerId, event, payload) {
  const socketId = call.sockets[peerId];
  if (socketId && io.sockets.sockets.has(socketId)) io.to(socketId).emit(event, payload);
  else emitToUser(peerId, event, payload);
}

function readSdp(data, field) {
  const value = data[field];
  if (typeof value === 'string') {
    if (value.length < 10 || value.length > 60000) throw fail(400, 'invalid_payload', `${field} is invalid`);
    return value;
  }
  if (isPlainObject(value) && typeof value.sdp === 'string' && value.sdp.length <= 60000 && ['offer', 'answer', 'pranswer', 'rollback'].includes(value.type)) {
    return { type: value.type, sdp: value.sdp };
  }
  throw fail(400, 'invalid_payload', `${field} is invalid`);
}

function readCandidate(data) {
  const value = data.candidate;
  if (value === null) return null;
  if (!isPlainObject(value) || typeof value.candidate !== 'string' || value.candidate.length > 2048) throw fail(400, 'invalid_payload', 'candidate is invalid');
  const candidate = { candidate: value.candidate };
  if (typeof value.sdpMid === 'string' && value.sdpMid.length <= 64) candidate.sdpMid = value.sdpMid;
  if (Number.isInteger(value.sdpMLineIndex) && value.sdpMLineIndex >= 0 && value.sdpMLineIndex <= 255) candidate.sdpMLineIndex = value.sdpMLineIndex;
  if (typeof value.usernameFragment === 'string' && value.usernameFragment.length <= 256) candidate.usernameFragment = value.usernameFragment;
  return candidate;
}

function relaySignal(socket, event, data, body) {
  const ctx = socket.data.ctx;
  checkRate('signal', ctx);
  const actorId = ctx.anonymousId;
  if (data.callId !== undefined) {
    const callId = readId(data, 'callId');
    const call = activeCalls.get(callId);
    if (!call || (call.callerId !== actorId && call.receiverId !== actorId)) throw fail(404, 'not_found', 'Call not found');
    const peerId = call.callerId === actorId ? call.receiverId : call.callerId;
    if (event === 'call:answer' && call.status === 'ringing') {
      if (call.receiverId !== actorId) throw fail(403, 'forbidden', 'Only the receiver can answer');
      activateCall(call, socket.id);
    }
    call.sockets[actorId] = socket.id;
    emitToCallPeer(call, peerId, event, { callId, conversationId: call.conversationId, ...body });
    return { callId };
  }
  if (data.transferId !== undefined) {
    const transferId = readId(data, 'transferId');
    const transfer = transfers.get(transferId);
    if (!transfer || (transfer.senderId !== actorId && transfer.receiverId !== actorId)) throw fail(404, 'not_found', 'Transfer not found');
    if (transfer.status !== 'accepted') throw fail(409, 'invalid_state', 'Transfer has not been accepted');
    const peerId = transfer.senderId === actorId ? transfer.receiverId : transfer.senderId;
    emitToUser(peerId, event, { transferId, conversationId: transfer.conversationId, ...body });
    return { transferId };
  }
  throw fail(400, 'invalid_payload', 'callId or transferId is required');
}

async function handleCallOffer(socket, data) {
  const ctx = socket.data.ctx;
  const sdp = readSdp(data, 'sdp');
  if (data.callId !== undefined || data.transferId !== undefined) return relaySignal(socket, 'call:offer', data, { sdp });
  checkRate('call', ctx);
  await assertAllowed(ctx, 'calls');
  const conversationId = readId(data, 'conversationId');
  const receiverId = readId(data, 'receiverId');
  const type = readEnum(data, 'type', ['voice', 'video']);
  const conversation = await assertPeers(conversationId, ctx.anonymousId, receiverId);
  await assertRoomFeature(conversation, 'calls');
  if (userCall.has(ctx.anonymousId)) throw fail(409, 'busy', 'You are already in a call');
  if (!isOnline(receiverId)) throw fail(409, 'receiver_offline', 'The other participant is offline');
  if (userCall.has(receiverId)) throw fail(409, 'receiver_busy', 'The other participant is in another call');
  const callId = randomId('call');
  const call = registerCall({ callId, conversationId, callerId: ctx.anonymousId, receiverId, type, status: 'ringing' });
  call.sockets[ctx.anonymousId] = socket.id;
  try {
    await CallSession.create({ callId, conversationId, callerId: ctx.anonymousId, receiverId, type, status: 'ringing', startedAt: new Date(), expiresAt: new Date(NOW() + 2592000000) });
  } catch (err) {
    unregisterCall(call);
    throw err;
  }
  emitToUser(receiverId, 'call:offer', { callId, conversationId, callerId: ctx.anonymousId, callerName: socket.data.displayName, type, sdp, expiresAt: new Date(NOW() + TIMING.callRingMs) });
  return { callId, status: 'ringing' };
}

function requireCallParticipant(socket, data, role) {
  const callId = readId(data, 'callId');
  const call = activeCalls.get(callId);
  const actorId = socket.data.ctx.anonymousId;
  if (!call || (call.callerId !== actorId && call.receiverId !== actorId)) throw fail(404, 'not_found', 'Call not found');
  if (role === 'receiver' && call.receiverId !== actorId) throw fail(403, 'forbidden', 'Only the receiver can do this');
  return call;
}

function handleCallAccept(socket, data) {
  const call = requireCallParticipant(socket, data, 'receiver');
  if (call.status !== 'ringing') throw fail(409, 'invalid_state', 'Call is not ringing');
  activateCall(call, socket.id);
  return { callId: call.callId, status: 'active' };
}

function handleCallReject(socket, data) {
  const call = requireCallParticipant(socket, data, 'receiver');
  if (call.status !== 'ringing') throw fail(409, 'invalid_state', 'Call is not ringing');
  const reason = readString(data, 'reason', { optional: true, min: 1, max: 32, pattern: /^[a-z_]+$/ }) || 'declined';
  endCall(call, { by: socket.data.ctx.anonymousId, reason, event: 'call:reject', status: 'rejected' });
  return { callId: call.callId };
}

function handleCallEnd(socket, data) {
  const call = requireCallParticipant(socket, data);
  endCall(call, { by: socket.data.ctx.anonymousId, reason: 'hangup' });
  return { callId: call.callId };
}

async function requestPeer(actor, data) {
  checkRate('peer', actor);
  await assertAllowed(actor, 'messaging');
  const receiverId = readId(data, 'receiverId');
  const conversationId = readId(data, 'conversationId', { optional: true }) || null;
  if (receiverId === actor.anonymousId) throw fail(400, 'invalid_payload', 'Cannot target yourself');
  if (!(await AnonymousIdentity.exists({ anonymousId: receiverId }))) throw fail(404, 'not_found', 'Identity not found');
  if (await isBlockedBetween(actor.anonymousId, receiverId)) throw fail(403, 'blocked', 'Interaction is not permitted');
  if (conversationId) await assertPeers(conversationId, actor.anonymousId, receiverId);
  if (!isOnline(receiverId)) throw fail(409, 'receiver_offline', 'The other participant is offline');
  let outgoing = 0;
  for (const request of peerRequests.values()) {
    if (request.fromId === actor.anonymousId) {
      if (request.toId === receiverId) return { requestId: request.requestId, status: 'pending' };
      outgoing += 1;
    }
  }
  if (outgoing >= 5) throw fail(429, 'too_many_pending', 'Too many pending peer requests');
  const requestId = randomId('pr', 9);
  const request = { requestId, fromId: actor.anonymousId, toId: receiverId, conversationId, expiresAt: NOW() + TIMING.peerRequestMs };
  peerRequests.set(requestId, request);
  const identity = await AnonymousIdentity.findOne({ anonymousId: actor.anonymousId }).select('displayName').lean();
  emitToUser(receiverId, 'peer:request', { requestId, senderId: actor.anonymousId, senderName: identity ? identity.displayName : null, conversationId, expiresAt: new Date(request.expiresAt) });
  return { requestId, status: 'pending' };
}

async function acceptPeer(actor, data) {
  const requestId = readId(data, 'requestId');
  const request = peerRequests.get(requestId);
  if (!request || request.toId !== actor.anonymousId || request.expiresAt <= NOW()) throw fail(404, 'not_found', 'Peer request not found');
  if (await isBlockedBetween(request.fromId, request.toId)) {
    peerRequests.delete(requestId);
    throw fail(403, 'blocked', 'Interaction is not permitted');
  }
  peerRequests.delete(requestId);
  const directKey = [request.fromId, request.toId].sort().join('|');
  let conversationId = null;
  if (request.conversationId) {
    try {
      const promoted = await Conversation.findOneAndUpdate(
        { conversationId: request.conversationId, type: 'direct', directKey: { $exists: false } },
        { $set: { ephemeral: false, directKey }, $unset: { expiresAt: 1 } },
        { returnDocument: 'after' }
      ).lean();
      if (promoted) conversationId = promoted.conversationId;
    } catch (err) {
      if (err.code !== 11000) throw err;
    }
  }
  if (!conversationId) conversationId = (await ensureDirectConversation(request.fromId, request.toId)).conversation.conversationId;
  const payload = { requestId, conversationId };
  emitToUser(request.fromId, 'peer:accept', { ...payload, peerId: request.toId });
  emitToUser(request.toId, 'peer:accept', { ...payload, peerId: request.fromId });
  return payload;
}

function rejectPeer(actor, data) {
  const requestId = readId(data, 'requestId');
  const request = peerRequests.get(requestId);
  if (!request || request.toId !== actor.anonymousId) throw fail(404, 'not_found', 'Peer request not found');
  peerRequests.delete(requestId);
  emitToUser(request.fromId, 'peer:reject', { requestId, peerId: request.toId });
  return { requestId };
}

const quotaPayload = (doc, conversationId) => {
  const used = doc ? doc.usedBytes : 0;
  const reserved = doc ? doc.reservedBytes : 0;
  const limit = doc ? doc.limitBytes : config.transferLimit;
  return { conversationId, limitBytes: limit, usedBytes: used, reservedBytes: reserved, remainingBytes: Math.max(0, limit - used - reserved) };
};

async function readQuota(conversationId, senderId) {
  const doc = await TransferQuota.findOne({ conversationId, senderId }).lean();
  return quotaPayload(doc, conversationId);
}

async function reserveQuota(conversationId, senderId, receiverId, transferId, bytes, expiresAt) {
  try {
    await TransferQuota.updateOne(
      { conversationId, senderId },
      { $setOnInsert: { receiverId, usedBytes: 0, reservedBytes: 0, limitBytes: config.transferLimit, reservations: [], createdAt: new Date(), updatedAt: new Date() } },
      { upsert: true }
    );
  } catch (err) {
    if (err.code !== 11000) throw err;
  }
  return TransferQuota.findOneAndUpdate(
    { conversationId, senderId, $expr: { $lte: [{ $add: ['$usedBytes', '$reservedBytes', bytes] }, '$limitBytes'] } },
    { $inc: { reservedBytes: bytes }, $set: { updatedAt: new Date() }, $push: { reservations: { transferId, bytes, expiresAt } } },
    { returnDocument: 'after' }
  ).lean();
}

function releaseReservation(conversationId, senderId, transferId, bytes) {
  return TransferQuota.updateOne(
    { conversationId, senderId, reservations: { $elemMatch: { transferId, bytes } } },
    { $inc: { reservedBytes: -bytes }, $pull: { reservations: { transferId } }, $set: { updatedAt: new Date() } }
  );
}

async function commitReservation(conversationId, senderId, transferId, bytes) {
  const result = await TransferQuota.updateOne(
    { conversationId, senderId, reservations: { $elemMatch: { transferId, bytes } } },
    { $inc: { reservedBytes: -bytes, usedBytes: bytes }, $pull: { reservations: { transferId } }, $set: { updatedAt: new Date() } }
  );
  if (!result.modifiedCount) {
    await TransferQuota.updateOne({ conversationId, senderId }, { $inc: { usedBytes: bytes }, $set: { updatedAt: new Date() } });
  }
}

function unregisterTransfer(transfer, finalStatus) {
  clearTimeout(transfer.timer);
  transfers.delete(transfer.transferId);
  for (const id of [transfer.senderId, transfer.receiverId]) {
    const set = userTransfers.get(id);
    if (set) {
      set.delete(transfer.transferId);
      if (!set.size) userTransfers.delete(id);
    }
  }
  recentTransfers.set(transfer.transferId, { senderId: transfer.senderId, receiverId: transfer.receiverId, conversationId: transfer.conversationId, status: finalStatus, endedAt: NOW() });
}

function releaseTransferQuota(transfer) {
  releaseReservation(transfer.conversationId, transfer.senderId, transfer.transferId, transfer.size).catch((err) => logError('quota release failed', err));
}

function cancelTransfer(transfer, byId, reason) {
  if (!transfers.has(transfer.transferId)) return false;
  unregisterTransfer(transfer, transfer.status === 'accepted' ? 'accepted' : 'cancelled');
  releaseTransferQuota(transfer);
  const payload = { transferId: transfer.transferId, conversationId: transfer.conversationId, reason, by: byId };
  [transfer.senderId, transfer.receiverId].filter((id) => id !== byId).forEach((id) => emitToUser(id, 'transfer:cancel', payload));
  log('transfer negotiated', { transfer: shortId(transfer.transferId), result: 'cancelled', reason });
  return true;
}

function cancelUserTransfers(anonymousId, reason) {
  const set = userTransfers.get(anonymousId);
  if (!set) return;
  for (const id of [...set]) {
    const transfer = transfers.get(id);
    if (transfer) cancelTransfer(transfer, anonymousId, reason);
  }
}

function cancelConversationTransfers(conversationId, reason) {
  for (const transfer of [...transfers.values()]) {
    if (transfer.conversationId === conversationId) cancelTransfer(transfer, null, reason);
  }
}

function abortConversationActivity(conversationId, reason) {
  cancelConversationTransfers(conversationId, reason);
  for (const call of [...activeCalls.values()]) {
    if (call.conversationId === conversationId) endCall(call, { by: null, reason });
  }
}

async function requestTransfer(socket, data) {
  const ctx = socket.data.ctx;
  checkRate('transfer', ctx);
  await assertAllowed(ctx, 'transfers');
  const transferId = readId(data, 'transferId', { optional: true }) || randomId('tr');
  const conversationId = readId(data, 'conversationId');
  const receiverId = readId(data, 'receiverId');
  const fileName = sanitizeFileName(readString(data, 'fileName', { min: 1, max: 255 }));
  const mimeType = readString(data, 'mimeType', { min: 3, max: 127, pattern: MIME_PATTERN }).toLowerCase();
  const size = readInt(data, 'size', { min: 1, max: 1099511627776 });
  const kind = readEnum(data, 'kind', ['file', 'image', 'video', 'audio', 'voice', 'document', 'archive'], { optional: true })
    || (mimeType.startsWith('image/') ? 'image' : mimeType.startsWith('video/') ? 'video' : mimeType.startsWith('audio/') ? 'audio' : 'file');
  if (transfers.has(transferId) || recentTransfers.has(transferId)) throw fail(409, 'conflict', 'transferId already used');
  const conversation = await assertPeers(conversationId, ctx.anonymousId, receiverId);
  await assertRoomFeature(conversation, 'transfers');
  if (kind === 'voice') await assertRoomFeature(conversation, 'voice');
  if (!isOnline(receiverId)) throw fail(409, 'receiver_offline', 'The other participant is offline');
  const active = userTransfers.get(ctx.anonymousId);
  if (active && active.size >= 3) throw fail(429, 'too_many_transfers', 'Too many active transfers');
  const quota = await reserveQuota(conversationId, ctx.anonymousId, conversation.type === 'direct' ? receiverId : null, transferId, size, new Date(NOW() + TIMING.transferMaxMs + 120000));
  if (!quota) {
    const current = await readQuota(conversationId, ctx.anonymousId);
    throw fail(413, 'quota_exceeded', 'The transfer exceeds the remaining transfer allowance', { remainingBytes: current.remainingBytes, limitBytes: current.limitBytes });
  }
  if (transfers.has(transferId)) {
    releaseReservation(conversationId, ctx.anonymousId, transferId, size).catch(() => {});
    throw fail(409, 'conflict', 'transferId already used');
  }
  const transfer = { transferId, conversationId, senderId: ctx.anonymousId, receiverId, fileName, mimeType, size, kind, status: 'requested', createdAt: NOW(), timer: null };
  transfer.timer = setTimeout(() => cancelTransfer(transfer, null, 'expired'), TIMING.transferRequestMs);
  transfers.set(transferId, transfer);
  for (const id of [ctx.anonymousId, receiverId]) {
    if (!userTransfers.has(id)) userTransfers.set(id, new Set());
    userTransfers.get(id).add(transferId);
  }
  emitToUser(receiverId, 'transfer:request', { transferId, conversationId, senderId: ctx.anonymousId, fileName, mimeType, size, kind, expiresAt: new Date(NOW() + TIMING.transferRequestMs) });
  return { transferId, status: 'requested', remainingBytes: Math.max(0, quota.limitBytes - quota.usedBytes - quota.reservedBytes) };
}

function requireTransferParticipant(socket, data, role) {
  const transferId = readId(data, 'transferId');
  const transfer = transfers.get(transferId);
  const actorId = socket.data.ctx.anonymousId;
  if (!transfer || (transfer.senderId !== actorId && transfer.receiverId !== actorId)) throw fail(404, 'not_found', 'Transfer not found');
  if (role === 'receiver' && transfer.receiverId !== actorId) throw fail(403, 'forbidden', 'Only the receiver can do this');
  return transfer;
}

async function acceptTransfer(socket, data) {
  const transfer = requireTransferParticipant(socket, data, 'receiver');
  if (transfer.status !== 'requested') throw fail(409, 'invalid_state', 'Transfer is not awaiting acceptance');
  await assertAllowed(socket.data.ctx, 'transfers');
  if (await isBlockedBetween(transfer.senderId, transfer.receiverId)) {
    cancelTransfer(transfer, null, 'blocked');
    throw fail(403, 'blocked', 'Interaction is not permitted');
  }
  if (!transfers.has(transfer.transferId) || transfer.status !== 'requested') throw fail(409, 'invalid_state', 'Transfer is no longer available');
  clearTimeout(transfer.timer);
  transfer.status = 'accepted';
  transfer.timer = setTimeout(() => cancelTransfer(transfer, null, 'timeout'), TIMING.transferMaxMs);
  emitToUser(transfer.senderId, 'transfer:accept', { transferId: transfer.transferId, conversationId: transfer.conversationId, receiverId: transfer.receiverId, iceServers: buildIceServers() });
  log('transfer negotiated', { transfer: shortId(transfer.transferId), result: 'accepted' });
  return { transferId: transfer.transferId, status: 'accepted', iceServers: buildIceServers() };
}

function rejectTransfer(socket, data) {
  const transfer = requireTransferParticipant(socket, data, 'receiver');
  if (transfer.status !== 'requested') throw fail(409, 'invalid_state', 'Transfer is not awaiting acceptance');
  const reason = readString(data, 'reason', { optional: true, min: 1, max: 32, pattern: /^[a-z_]+$/ }) || 'declined';
  unregisterTransfer(transfer, 'rejected');
  releaseTransferQuota(transfer);
  emitToUser(transfer.senderId, 'transfer:reject', { transferId: transfer.transferId, conversationId: transfer.conversationId, reason });
  log('transfer negotiated', { transfer: shortId(transfer.transferId), result: 'rejected' });
  return { transferId: transfer.transferId };
}

function cancelTransferHandler(socket, data) {
  const transfer = requireTransferParticipant(socket, data);
  const reason = readString(data, 'reason', { optional: true, min: 1, max: 32, pattern: /^[a-z_]+$/ }) || 'cancelled';
  cancelTransfer(transfer, socket.data.ctx.anonymousId, reason);
  return { transferId: transfer.transferId };
}

async function completeTransfer(socket, data) {
  const transferId = readId(data, 'transferId');
  const actorId = socket.data.ctx.anonymousId;
  const transfer = transfers.get(transferId);
  if (!transfer) {
    const recent = recentTransfers.get(transferId);
    if (recent && recent.status === 'completed' && (recent.senderId === actorId || recent.receiverId === actorId)) return { transferId, status: 'completed' };
    throw fail(404, 'not_found', 'Transfer not found');
  }
  if (transfer.senderId !== actorId && transfer.receiverId !== actorId) throw fail(404, 'not_found', 'Transfer not found');
  if (transfer.status !== 'accepted') throw fail(409, 'invalid_state', 'Transfer has not been accepted');
  if (transfer.completing) return { transferId, status: 'completed' };
  transfer.completing = true;
  try {
    await commitReservation(transfer.conversationId, transfer.senderId, transferId, transfer.size);
  } catch (err) {
    transfer.completing = false;
    throw err;
  }
  unregisterTransfer(transfer, 'completed');
  const peerId = transfer.senderId === actorId ? transfer.receiverId : transfer.senderId;
  emitToUser(peerId, 'transfer:complete', { transferId, conversationId: transfer.conversationId, size: transfer.size });
  log('transfer negotiated', { transfer: shortId(transferId), result: 'completed' });
  return { transferId, status: 'completed' };
}

async function handleUserGone(anonymousId) {
  if (isOnline(anonymousId)) return;
  const matchId = userMatch.get(anonymousId);
  if (matchId) await endMatch(matchId, anonymousId, 'disconnected');
  endUserCall(anonymousId, 'disconnected');
  cancelUserTransfers(anonymousId, 'disconnected');
  for (const [id, request] of peerRequests) {
    if (request.fromId === anonymousId || request.toId === anonymousId) peerRequests.delete(id);
  }
}

app.set('trust proxy', config.trustProxyHops);
app.disable('x-powered-by');
app.use(cors({
  origin: (origin, callback) => (originAllowed(origin) ? callback(null, true) : callback(null, false)),
  credentials: true,
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '32kb' }));

app.use((req, res, next) => {
  req.ipHash = ipHashOf(resolveIp(req.headers, req.socket.remoteAddress));
  next();
});

function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const match = /^Bearer\s+(.+)$/.exec(header);
  if (!match) return next(fail(401, 'missing_session', 'Authorization header with a bearer session token is required'));
  resolveSession(match[1], req.ipHash)
    .then((ctx) => { req.ctx = ctx; next(); })
    .catch(next);
}

function requireAdmin(req, res, next) {
  try {
    checkRate('adminAuth', { ipHash: req.ipHash });
  } catch (err) {
    return next(err);
  }
  const header = req.headers['x-admin-secret'];
  if (!ADMIN_SECRET || typeof header !== 'string' || !safeEqual(header, ADMIN_SECRET)) return next(fail(401, 'unauthorized', 'Invalid admin credentials'));
  next();
}

app.get('/api/v1/health', asyncRoute(async (req, res) => {
  res.json({
    status: dbReady() ? 'ok' : 'degraded',
    database: dbReady() ? 'connected' : 'disconnected',
    uptime: Math.floor(process.uptime())
  });
}));

app.get('/api/v1/config/ice-servers', (req, res) => {
  res.json({ iceServers: buildIceServers() });
});

app.get('/api/v1/matchmaking/interests', (req, res) => {
  res.json({ suggested: SUGGESTED_INTERESTS });
});

app.post('/api/v1/session', asyncRoute(async (req, res) => {
  checkRate('session', { ipHash: req.ipHash });
  const body = asObject(req.body);
  const displayName = sanitizeDisplayName(body.displayName) || randomDisplayName();
  const publicKey = readString(body, 'publicKey', { optional: true, min: 16, max: 4096, pattern: BASE64_PATTERN });
  const devicePublicKey = readString(body, 'devicePublicKey', { optional: true, min: 16, max: 4096, pattern: BASE64_PATTERN });
  const algorithm = readEnum(body, 'keyAlgorithm', KEY_ALGORITHMS, { optional: true }) || 'ECDH-P256';
  const deviceHash = devicePublicKey ? deviceHashOf(devicePublicKey) : null;
  if (deviceHash) checkRate('session', { ipHash: req.ipHash, deviceHash }, 'device');
  await assertAllowed({ ipHash: req.ipHash, deviceHash }, 'session');
  const anonymousId = randomId('anon', 9);
  const identityHash = identityHashOf(anonymousId);
  const now = new Date();
  const identityDoc = {
    anonymousId,
    identityHash,
    displayName,
    currentKeyVersion: publicKey ? 1 : 0,
    keys: publicKey ? [{ version: 1, publicKey, algorithm, createdAt: now }] : [],
    createdAt: now,
    lastSeenAt: now,
    expiresAt: new Date(NOW() + config.sessionTtlMs + config.identityRetentionMs)
  };
  const identity = await AnonymousIdentity.create(identityDoc);
  const { token, expiresAt } = await issueSession(identity, deviceHash, req.ipHash);
  await touchDevice(deviceHash, anonymousId);
  log('session created', { anon: shortId(anonymousId) });
  res.status(201).json(sessionPayload(identity, token, expiresAt));
}));

app.post('/api/v1/session/refresh', requireAuth, asyncRoute(async (req, res) => {
  await assertAllowed(req.ctx, 'session');
  const expiresAt = new Date(NOW() + config.sessionTtlMs);
  await UserSession.updateOne({ tokenHash: req.ctx.tokenHash }, { $set: { expiresAt, lastSeenAt: new Date() } });
  const cached = sessionCache.get(req.ctx.tokenHash);
  if (cached) cached.expiresAt = expiresAt.getTime();
  const identity = await AnonymousIdentity.findOneAndUpdate({ anonymousId: req.ctx.anonymousId }, { $set: { expiresAt: new Date(expiresAt.getTime() + config.identityRetentionMs), lastSeenAt: new Date() } }, { returnDocument: 'after' }).lean();
  if (!identity) throw fail(404, 'not_found', 'Identity no longer exists');
  res.json(sessionPayload(identity, req.headers.authorization.split(' ')[1], expiresAt));
}));

app.delete('/api/v1/session', requireAuth, asyncRoute(async (req, res) => {
  await UserSession.deleteOne({ tokenHash: req.ctx.tokenHash });
  invalidateSession(req.ctx.tokenHash);
  for (const socket of io.sockets.sockets.values()) {
    if (socket.data.ctx && socket.data.ctx.tokenHash === req.ctx.tokenHash) socket.disconnect(true);
  }
  res.status(204).end();
}));

app.post('/api/v1/identity/keys', requireAuth, asyncRoute(async (req, res) => {
  checkRate('keyRotate', req.ctx);
  const body = asObject(req.body);
  const publicKey = readString(body, 'publicKey', { min: 16, max: 4096, pattern: BASE64_PATTERN });
  const algorithm = readEnum(body, 'algorithm', KEY_ALGORITHMS, { optional: true }) || 'ECDH-P256';
  const identity = await AnonymousIdentity.findOne({ anonymousId: req.ctx.anonymousId }).select('keys currentKeyVersion').lean();
  if (!identity) throw fail(404, 'not_found', 'Identity not found');
  const version = identity.currentKeyVersion + 1;
  const keys = identity.keys.concat({ version, publicKey, algorithm, createdAt: new Date() }).slice(-KEY_HISTORY_LIMIT);
  await AnonymousIdentity.updateOne({ anonymousId: req.ctx.anonymousId }, { $set: { keys, currentKeyVersion: version } });
  emitToUser(req.ctx.anonymousId, 'identity:key_rotated', { anonymousId: req.ctx.anonymousId, keyVersion: version });
  res.status(201).json({ anonymousId: req.ctx.anonymousId, keyVersion: version, publicKey, algorithm });
}));

app.get('/api/v1/identity/:anonymousId/keys', requireAuth, asyncRoute(async (req, res) => {
  const anonymousId = readId({ id: req.params.anonymousId }, 'id');
  const identity = await AnonymousIdentity.findOne({ anonymousId }).select('displayName currentKeyVersion keys').lean();
  if (!identity) throw fail(404, 'not_found', 'Identity not found');
  const includeHistory = req.query.history === 'true';
  res.json({
    anonymousId,
    displayName: identity.displayName,
    currentKeyVersion: identity.currentKeyVersion,
    currentKey: currentKeyOf(identity),
    history: includeHistory ? identity.keys.map((key) => ({ version: key.version, publicKey: key.publicKey, algorithm: key.algorithm, createdAt: key.createdAt })) : undefined
  });
}));

app.post('/api/v1/conversations', requireAuth, asyncRoute(async (req, res) => {
  checkRate('conversation', req.ctx);
  await assertAllowed(req.ctx, 'messaging');
  const body = asObject(req.body);
  const type = readEnum(body, 'type', ['direct', 'group'], { optional: true }) || (body.memberIds && body.memberIds.length > 1 ? 'group' : 'direct');
  if (type === 'direct') {
    const targetId = readId(body, 'memberId', { optional: true }) || (Array.isArray(body.memberIds) ? body.memberIds[0] : undefined);
    if (!targetId || !ID_PATTERN.test(targetId)) throw fail(400, 'invalid_payload', 'memberId is required for a direct conversation');
    if (targetId === req.ctx.anonymousId) throw fail(400, 'invalid_payload', 'Cannot start a conversation with yourself');
    if (!(await AnonymousIdentity.exists({ anonymousId: targetId }))) throw fail(404, 'not_found', 'Identity not found');
    if (await isBlockedBetween(req.ctx.anonymousId, targetId)) throw fail(403, 'blocked', 'Interaction is not permitted');
    const { conversation } = await ensureDirectConversation(req.ctx.anonymousId, targetId);
    return res.status(201).json(serializeConversation(conversation));
  }
  const { conversation, skipped } = await createGroupConversation(req.ctx.anonymousId, body);
  res.status(201).json(serializeConversation(conversation, { skippedMembers: skipped }));
}));

app.get('/api/v1/conversations', requireAuth, asyncRoute(async (req, res) => {
  const limit = clampQueryInt(req.query.limit, 1, 100, 30);
  const memberships = await ConversationMember.find({ anonymousId: req.ctx.anonymousId }).sort({ joinedAt: -1 }).select('conversationId lastReadAt').lean();
  if (!memberships.length) return res.json({ conversations: [] });
  const readMap = new Map(memberships.map((item) => [item.conversationId, item.lastReadAt]));
  const conversations = await Conversation.find({ conversationId: { $in: memberships.map((item) => item.conversationId) } }).sort({ activityAt: -1 }).limit(limit).lean();
  res.json({ conversations: conversations.filter(conversationLive).map((conversation) => serializeConversation(conversation, { lastReadAt: readMap.get(conversation.conversationId) || null })) });
}));

app.get('/api/v1/conversations/:id', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  const { conversation } = await loadMembership(conversationId, req.ctx.anonymousId);
  const members = await ConversationMember.find({ conversationId }).lean();
  const identities = await loadIdentitySummaries(members.map((member) => member.anonymousId));
  res.json(serializeConversation(conversation, { members: members.map((member) => serializeMember(member, identities)) }));
}));

app.patch('/api/v1/conversations/:id', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  const updated = await updateConversation(req.ctx.anonymousId, conversationId, asObject(req.body));
  res.json(serializeConversation(updated));
}));

app.post('/api/v1/conversations/:id/members', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  const body = asObject(req.body);
  const ids = readIdArray(body, 'memberIds', { optional: true, max: 50 }) || (body.memberId ? [readId(body, 'memberId')] : []);
  if (!ids.length) throw fail(400, 'invalid_payload', 'memberIds is required');
  const result = await addMembers(req.ctx.anonymousId, conversationId, ids);
  res.status(201).json(result);
}));

app.patch('/api/v1/conversations/:id/members/:userId', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  const targetId = readId({ id: req.params.userId }, 'id');
  const role = readEnum(asObject(req.body), 'role', ROLES);
  const result = await changeMemberRole(req.ctx.anonymousId, conversationId, targetId, role);
  res.json(result);
}));

app.delete('/api/v1/conversations/:id/members/:userId', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  const targetId = readId({ id: req.params.userId }, 'id');
  const result = await removeMember(req.ctx.anonymousId, conversationId, targetId);
  res.json(result);
}));

app.get('/api/v1/conversations/:id/messages', requireAuth, asyncRoute(async (req, res) => {
  checkRate('read', req.ctx);
  const conversationId = readId({ id: req.params.id }, 'id');
  const result = await listMessages(req.ctx.anonymousId, conversationId, req.query);
  res.json(result);
}));

app.post('/api/v1/conversations/:id/messages', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  const result = await createMessage(req.ctx, conversationId, asObject(req.body));
  res.status(result.duplicate ? 200 : 201).json(result.message);
}));

app.delete('/api/v1/messages/:id', requireAuth, asyncRoute(async (req, res) => {
  const messageId = readId({ id: req.params.id }, 'id');
  const result = await deleteMessage(req.ctx.anonymousId, messageId);
  res.json(result);
}));

app.post('/api/v1/messages/:id/reactions', requireAuth, asyncRoute(async (req, res) => {
  const messageId = readId({ id: req.params.id }, 'id');
  const result = await setReaction(req.ctx, messageId, asObject(req.body));
  res.status(201).json(result);
}));

app.post('/api/v1/messages/delivered', requireAuth, asyncRoute(async (req, res) => {
  const result = await markDelivered(req.ctx, asObject(req.body));
  res.json(result);
}));

app.post('/api/v1/messages/read', requireAuth, asyncRoute(async (req, res) => {
  const result = await markRead(req.ctx, asObject(req.body));
  res.json(result);
}));

app.get('/api/v1/conversations/:id/quota', requireAuth, asyncRoute(async (req, res) => {
  const conversationId = readId({ id: req.params.id }, 'id');
  await loadMembership(conversationId, req.ctx.anonymousId);
  const result = await readQuota(conversationId, req.ctx.anonymousId);
  res.json(result);
}));

app.post('/api/v1/matchmaking/join', requireAuth, asyncRoute(async (req, res) => {
  const prefs = parseMatchPreferences(asObject(req.body));
  const result = await joinMatchmaking(req.ctx, prefs);
  res.json(result);
}));

app.post('/api/v1/matchmaking/leave', requireAuth, asyncRoute(async (req, res) => {
  const result = await leaveMatchmaking(req.ctx);
  res.json(result);
}));

app.get('/api/v1/matchmaking/status', requireAuth, asyncRoute(async (req, res) => {
  res.json(matchStatus(req.ctx.anonymousId));
}));

app.post('/api/v1/rooms', requireAuth, asyncRoute(async (req, res) => {
  const room = await createRoom(req.ctx, asObject(req.body));
  res.status(201).json(room);
}));

app.get('/api/v1/rooms/:id', requireAuth, asyncRoute(async (req, res) => {
  const roomId = readId({ id: req.params.id }, 'id');
  const room = await Room.findOne({ roomId, expiresAt: { $gt: new Date() } }).lean();
  if (!room) throw fail(404, 'not_found', 'Room not found');
  const isMember = await RoomMember.exists({ roomId, anonymousId: req.ctx.anonymousId });
  res.json(serializeRoom(room, { conversationId: isMember ? room.conversationId : undefined, isMember: !!isMember }));
}));

app.post('/api/v1/rooms/:id/join', requireAuth, asyncRoute(async (req, res) => {
  const roomId = readId({ id: req.params.id }, 'id');
  const room = await joinRoom(req.ctx, roomId, asObject(req.body));
  res.json(room);
}));

app.post('/api/v1/rooms/:id/leave', requireAuth, asyncRoute(async (req, res) => {
  const roomId = readId({ id: req.params.id }, 'id');
  const result = await leaveRoom(req.ctx, roomId);
  res.json(result);
}));

app.delete('/api/v1/rooms/:id', requireAuth, asyncRoute(async (req, res) => {
  const roomId = readId({ id: req.params.id }, 'id');
  const result = await closeRoom(req.ctx, roomId);
  res.json(result);
}));

app.post('/api/v1/blocks', requireAuth, asyncRoute(async (req, res) => {
  const result = await blockUser(req.ctx, asObject(req.body));
  res.status(201).json(result);
}));

app.get('/api/v1/blocks', requireAuth, asyncRoute(async (req, res) => {
  const blocks = await Block.find({ blockerId: req.ctx.anonymousId }).sort({ createdAt: -1 }).lean();
  res.json({ blocks: blocks.map((block) => ({ anonymousId: block.blockedId, createdAt: block.createdAt })) });
}));

app.delete('/api/v1/blocks/:anonymousId', requireAuth, asyncRoute(async (req, res) => {
  const targetId = readId({ id: req.params.anonymousId }, 'id');
  const result = await unblockUser(req.ctx, targetId);
  res.json(result);
}));

app.post('/api/v1/reports', requireAuth, asyncRoute(async (req, res) => {
  const result = await createReport(req.ctx, asObject(req.body));
  res.status(201).json(result);
}));

app.post('/api/v1/moderation/events', requireAuth, asyncRoute(async (req, res) => {
  const result = await recordModerationEvent(req.ctx, asObject(req.body));
  res.status(201).json(result);
}));

app.get('/api/v1/admin/stats', requireAdmin, asyncRoute(async (req, res) => {
  const memory = process.memoryUsage();
  let diskUsage = null;
  try {
    const stats = await fs.promises.statfs('/');
    diskUsage = { totalBytes: stats.blocks * stats.bsize, freeBytes: stats.bfree * stats.bsize };
  } catch (err) {
    diskUsage = null;
  }
  res.json({
    activeUsers: userSockets.size,
    activeRooms: await Room.countDocuments({ expiresAt: { $gt: new Date() } }),
    activeCalls: activeCalls.size,
    activeTransfers: transfers.size,
    activeMatches: activeMatches.size,
    queuedText: matchQueues.text.size,
    queuedVideo: matchQueues.video.size,
    databaseStatus: dbReady() ? 'connected' : 'disconnected',
    uptime: Math.floor(process.uptime()),
    memoryUsage: { rss: memory.rss, heapUsed: memory.heapUsed, heapTotal: memory.heapTotal },
    diskUsage
  });
}));

app.get('/api/v1/admin/bans', requireAdmin, asyncRoute(async (req, res) => {
  const limit = clampQueryInt(req.query.limit, 1, 200, 50);
  const filter = {};
  const status = req.query.status;
  if (typeof status === 'string' && ['active', 'expired', 'lifted'].includes(status)) filter.status = status;
  const bans = await Ban.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
  res.json({ bans });
}));

app.post('/api/v1/admin/bans', requireAdmin, asyncRoute(async (req, res) => {
  const body = asObject(req.body);
  const scope = readEnum(body, 'scope', ['identity', 'device', 'ip', 'combined']);
  const banType = readEnum(body, 'banType', BAN_TYPES);
  const reason = readString(body, 'reason', { optional: true, min: 1, max: 300 }) || null;
  const restrictions = readIdArray(body, 'restrictions', { optional: true }) || FULL_RESTRICTIONS.slice();
  for (const restriction of restrictions) {
    if (!RESTRICTIONS.includes(restriction)) throw fail(400, 'invalid_payload', 'restrictions contains an invalid value');
  }
  const identityHash = readString(body, 'anonymousId', { optional: true, min: 6, max: 64, pattern: ID_PATTERN });
  const deviceHash = readString(body, 'deviceHash', { optional: true, min: 32, max: 128, pattern: /^[a-f0-9]+$/ });
  const rawIp = readString(body, 'ip', { optional: true, min: 3, max: 64 });
  const durationSeconds = readInt(body, 'durationSeconds', { optional: true, min: 60 });
  const ban = await createBan({
    scope,
    identityHash: identityHash ? identityHashOf(identityHash) : null,
    deviceHash: deviceHash || null,
    ipHash: rawIp ? ipHashOf(normalizeIp(rawIp)) : null,
    banType,
    restrictions,
    reason,
    source: 'admin',
    durationMs: durationSeconds ? durationSeconds * 1000 : null
  });
  applyBanToConnected(ban);
  res.status(201).json(ban.toObject());
}));

app.delete('/api/v1/admin/bans/:id', requireAdmin, asyncRoute(async (req, res) => {
  const banId = readId({ id: req.params.id }, 'id');
  const ban = await Ban.findOneAndUpdate({ banId }, { $set: { status: 'lifted' } }, { returnDocument: 'after' }).lean();
  if (!ban) throw fail(404, 'not_found', 'Ban not found');
  restrictionCache.clear();
  res.json({ banId, status: 'lifted' });
}));

app.use((req, res) => {
  res.status(404).json({ error: { code: 'not_found', message: 'Route not found' } });
});

app.use((err, req, res, next) => {
  const described = describeError(err);
  res.status(described.status).json({ error: { code: described.code, message: described.message, retryAfterMs: described.retryAfterMs, restriction: described.restriction, expiresAt: described.expiresAt } });
});

io.use((socket, next) => {
  const ipHash = ipHashOf(resolveIp(socket.handshake.headers, socket.handshake.address));
  socket.data.ipHash = ipHash;
  try {
    checkRate('socketConnect', { ipHash });
  } catch (err) {
    return next(new Error('rate_limited'));
  }
  const token = socket.handshake.auth && socket.handshake.auth.token;
  resolveSession(token, ipHash)
    .then(async (ctx) => {
      try {
        checkRate('socketConnect', ctx, 'identity');
        await assertAllowed(ctx, 'session');
      } catch (err) {
        return next(new Error(err.code || 'forbidden'));
      }
      const current = userSockets.get(ctx.anonymousId);
      if (current && current.size >= config.maxSocketsPerIdentity) return next(new Error('too_many_connections'));
      socket.data.ctx = ctx;
      next();
    })
    .catch(() => next(new Error('invalid_session')));
});

function wrapAck(socket, event, handler) {
  return (data, ack) => {
    const respond = typeof ack === 'function' ? ack : () => {};
    Promise.resolve()
      .then(() => {
        checkRate('socketEvent', socket.data.ctx);
        return handler(socket, asObject(data));
      })
      .then((result) => respond({ ok: true, data: result || {} }))
      .catch((err) => {
        const described = describeError(err);
        respond({ ok: false, error: { code: described.code, message: described.message, retryAfterMs: described.retryAfterMs, restriction: described.restriction } });
        if (described.status >= 500) logError(`socket event ${event} failed`, err);
      });
  };
}

io.on('connection', (socket) => {
  const ctx = socket.data.ctx;
  if (!userSockets.has(ctx.anonymousId)) userSockets.set(ctx.anonymousId, new Set());
  const wasOffline = userSockets.get(ctx.anonymousId).size === 0;
  userSockets.get(ctx.anonymousId).add(socket.id);
  socket.join(`user:${ctx.anonymousId}`);
  const pendingDisconnect = disconnectTimers.get(ctx.anonymousId);
  if (pendingDisconnect) {
    clearTimeout(pendingDisconnect);
    disconnectTimers.delete(ctx.anonymousId);
  }
  log('socket connected', { anon: shortId(ctx.anonymousId), fresh: wasOffline });

  AnonymousIdentity.findOne({ anonymousId: ctx.anonymousId }).select('displayName').lean()
    .then((identity) => { socket.data.displayName = identity ? identity.displayName : null; })
    .catch(() => { socket.data.displayName = null; });

  ConversationMember.find({ anonymousId: ctx.anonymousId }).select('conversationId').lean()
    .then((memberships) => memberships.forEach((membership) => socket.join(`conv:${membership.conversationId}`)))
    .catch((err) => logError('failed to join conversation rooms', err));

  socket.on('match:join', wrapAck(socket, 'match:join', (s, data) => joinMatchmaking(s.data.ctx, parseMatchPreferences(data))));
  socket.on('match:leave', wrapAck(socket, 'match:leave', (s) => leaveMatchmaking(s.data.ctx)));

  socket.on('call:offer', wrapAck(socket, 'call:offer', handleCallOffer));
  socket.on('call:answer', wrapAck(socket, 'call:answer', (s, data) => relaySignal(s, 'call:answer', data, { sdp: readSdp(data, 'sdp') })));
  socket.on('call:ice', wrapAck(socket, 'call:ice', (s, data) => relaySignal(s, 'call:ice', data, { candidate: readCandidate(data) })));
  socket.on('call:accept', wrapAck(socket, 'call:accept', handleCallAccept));
  socket.on('call:reject', wrapAck(socket, 'call:reject', handleCallReject));
  socket.on('call:end', wrapAck(socket, 'call:end', handleCallEnd));

  socket.on('peer:request', wrapAck(socket, 'peer:request', (s, data) => requestPeer(s.data.ctx, data)));
  socket.on('peer:accept', wrapAck(socket, 'peer:accept', (s, data) => acceptPeer(s.data.ctx, data)));
  socket.on('peer:reject', wrapAck(socket, 'peer:reject', (s, data) => rejectPeer(s.data.ctx, data)));

  socket.on('transfer:request', wrapAck(socket, 'transfer:request', requestTransfer));
  socket.on('transfer:accept', wrapAck(socket, 'transfer:accept', acceptTransfer));
  socket.on('transfer:reject', wrapAck(socket, 'transfer:reject', (s, data) => rejectTransfer(s, data)));
  socket.on('transfer:cancel', wrapAck(socket, 'transfer:cancel', (s, data) => cancelTransferHandler(s, data)));
  socket.on('transfer:complete', wrapAck(socket, 'transfer:complete', completeTransfer));
  socket.on('transfer:signal', wrapAck(socket, 'transfer:signal', (s, data) => {
    const transferId = readId(data, 'transferId');
    const transfer = transfers.get(transferId);
    const actorId = s.data.ctx.anonymousId;
    if (!transfer || (transfer.senderId !== actorId && transfer.receiverId !== actorId) || transfer.status !== 'accepted') throw fail(404, 'not_found', 'Transfer not found');
    const payload = isPlainObject(data.payload) ? data.payload : {};
    if (JSON.stringify(payload).length > 4096) throw fail(400, 'invalid_payload', 'payload too large');
    const peerId = transfer.senderId === actorId ? transfer.receiverId : transfer.senderId;
    emitToUser(peerId, 'transfer:signal', { transferId, conversationId: transfer.conversationId, payload });
    return { transferId };
  }));

  socket.on('message:new', wrapAck(socket, 'message:new', async (s, data) => {
    const conversationId = readId(data, 'conversationId');
    const result = await createMessage(s.data.ctx, conversationId, data);
    return result.message;
  }));
  socket.on('message:delivered', wrapAck(socket, 'message:delivered', (s, data) => markDelivered(s.data.ctx, data)));
  socket.on('message:read', wrapAck(socket, 'message:read', (s, data) => markRead(s.data.ctx, data)));
  socket.on('message:deleted', wrapAck(socket, 'message:deleted', (s, data) => deleteMessage(s.data.ctx.anonymousId, readId(data, 'messageId'))));
  socket.on('message:reaction', wrapAck(socket, 'message:reaction', (s, data) => setReaction(s.data.ctx, readId(data, 'messageId'), data)));

  socket.on('typing:start', wrapAck(socket, 'typing:start', async (s, data) => {
    checkRate('typing', s.data.ctx);
    const conversationId = readId(data, 'conversationId');
    await loadMembership(conversationId, s.data.ctx.anonymousId);
    socket.to(`conv:${conversationId}`).emit('typing:start', { conversationId, anonymousId: s.data.ctx.anonymousId });
    return { conversationId };
  }));
  socket.on('typing:stop', wrapAck(socket, 'typing:stop', async (s, data) => {
    const conversationId = readId(data, 'conversationId');
    await loadMembership(conversationId, s.data.ctx.anonymousId);
    socket.to(`conv:${conversationId}`).emit('typing:stop', { conversationId, anonymousId: s.data.ctx.anonymousId });
    return { conversationId };
  }));

  socket.on('moderation:event', wrapAck(socket, 'moderation:event', (s, data) => recordModerationEvent(s.data.ctx, data)));

  socket.on('disconnect', () => {
    const set = userSockets.get(ctx.anonymousId);
    if (set) {
      set.delete(socket.id);
      if (!set.size) userSockets.delete(ctx.anonymousId);
    }
    log('socket disconnected', { anon: shortId(ctx.anonymousId) });
    if (!isOnline(ctx.anonymousId)) {
      const timer = setTimeout(() => {
        disconnectTimers.delete(ctx.anonymousId);
        if (!isOnline(ctx.anonymousId)) handleUserGone(ctx.anonymousId).catch((err) => logError('cleanup on disconnect failed', err));
      }, TIMING.disconnectGraceMs);
      disconnectTimers.set(ctx.anonymousId, timer);
    }
  });

  socket.on('error', (err) => logError('socket error', err));
});

const cleanupTimers = [];
function every(ms, fn) {
  const id = setInterval(() => {
    try {
      const result = fn();
      if (result && typeof result.catch === 'function') result.catch((err) => logError('cleanup task failed', err));
    } catch (err) {
      logError('cleanup task failed', err);
    }
  }, ms);
  id.unref();
  cleanupTimers.push(id);
}

every(5000, sweepQueues);
every(15000, sweepRateBuckets);
every(30000, () => {
  const now = NOW();
  for (const [transferId, entry] of recentTransfers) {
    if (now - entry.endedAt > 600000) recentTransfers.delete(transferId);
  }
  for (const [requestId, request] of peerRequests) {
    if (request.expiresAt <= now) peerRequests.delete(requestId);
  }
  for (const [key, entry] of pinAttempts) {
    if (entry.touchedAt + 3600000 < now) pinAttempts.delete(key);
  }
  for (const [tokenHash, entry] of sessionCache) {
    if (entry.expiresAt <= now) sessionCache.delete(tokenHash);
  }
  for (const [key, entry] of restrictionCache) {
    if (entry.at + 300000 < now) restrictionCache.delete(key);
  }
});
every(60000, async () => {
  if (!dbReady()) return;
  const now = new Date();
  const expired = await TransferQuota.find({ 'reservations.expiresAt': { $lt: now } }).select('conversationId senderId reservations').lean();
  for (const doc of expired) {
    const stale = doc.reservations.filter((reservation) => reservation.expiresAt < now);
    if (!stale.length) continue;
    const bytes = stale.reduce((sum, reservation) => sum + reservation.bytes, 0);
    await TransferQuota.updateOne(
      { conversationId: doc.conversationId, senderId: doc.senderId },
      { $inc: { reservedBytes: -bytes }, $pull: { reservations: { transferId: { $in: stale.map((r) => r.transferId) } } } }
    );
  }
});
every(300000, async () => {
  if (!dbReady()) return;
  const cutoff = new Date(NOW() - 3600000);
  await CallSession.updateMany({ status: 'ringing', startedAt: { $lt: cutoff } }, { $set: { status: 'missed', endedAt: new Date(), endReason: 'stale' } });
});

async function connectDatabase() {
  mongoose.connection.on('connected', () => log('database connected'));
  mongoose.connection.on('disconnected', () => log('database disconnected'));
  mongoose.connection.on('error', (err) => logError('database error', err));
  while (true) {
    try {
      await mongoose.connect(config.mongoUri, { serverSelectionTimeoutMS: 5000, autoIndex: !config.production });
      return;
    } catch (err) {
      logError('database connection failed, retrying in 5s', err);
      await sleep(5000);
    }
  }
}

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('shutdown initiated', { signal });
  cleanupTimers.forEach(clearInterval);
  const timeout = setTimeout(() => process.exit(1), 10000).unref();
  try {
    io.disconnectSockets(true);
    await new Promise((resolve) => io.close(() => resolve()));
    await new Promise((resolve) => server.close(() => resolve()));
    await mongoose.connection.close(false);
    clearTimeout(timeout);
    log('shutdown complete');
    process.exit(0);
  } catch (err) {
    logError('shutdown error', err);
    process.exit(1);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (err) => logError('uncaught exception', err));
process.on('unhandledRejection', (err) => logError('unhandled rejection', err));

async function start() {
  await connectDatabase();
  server.listen(config.port, () => log('server started', { port: config.port, env: config.production ? 'production' : 'development' }));
}

start();
