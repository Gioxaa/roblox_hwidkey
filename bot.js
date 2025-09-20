'use strict';

const { setTimeout: delay } = require('timers/promises');
const { URL } = require('url');
const {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  Client,
  GatewayIntentBits,
  InteractionType,
  ModalBuilder,
  REST,
  Routes,
  SlashCommandBuilder,
  TextInputBuilder,
  TextInputStyle,
} = require('discord.js');
const dotenv = require('dotenv');

dotenv.config();

const includeBot = (process.env.INCLUDE_DISCORD_BOT || '').toLowerCase() === 'true';
if (!includeBot) {
  console.log('INCLUDE_DISCORD_BOT is not set to true. Exiting Discord bot.');
  process.exit(0);
}

const discordToken = requireEnv('DISCORD_TOKEN');
const discordClientId = requireEnv('DISCORD_CLIENT_ID');
const issuerBaseUrl = requireEnv('ISSUER_BASE_URL');
const issuerUser = requireEnv('ISSUER_BASIC_USER');
const issuerPass = requireEnv('ISSUER_BASIC_PASS');
const guildId = process.env.DISCORD_GUILD_ID ? process.env.DISCORD_GUILD_ID.trim() : undefined;

const apiBase = normalizeBaseUrl(issuerBaseUrl);
const basicAuth = Buffer.from(`${issuerUser}:${issuerPass}`, 'utf8').toString('base64');
const tokenCache = new Map();
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once('ready', async () => {
  console.log(`Discord bot logged in as ${client.user.tag}`);
  await registerCommands();
});

client.on('interactionCreate', async (interaction) => {
  try {
    if (interaction.type === InteractionType.ApplicationCommand && interaction.isChatInputCommand()) {
      await handleSlashCommand(interaction);
      return;
    }
    if (interaction.type === InteractionType.ModalSubmit) {
      await handleModalSubmit(interaction);
      return;
    }
    if (interaction.isButton()) {
      await handleButton(interaction);
    }
  } catch (err) {
    console.error('Interaction handler error:', err);
    if (interaction.isRepliable()) {
      const message = 'Something went wrong. Please try again later.';
      if (interaction.deferred || interaction.replied) {
        await interaction.followUp({ content: message, ephemeral: true }).catch(() => {});
      } else {
        await interaction.reply({ content: message, ephemeral: true }).catch(() => {});
      }
    }
  }
});

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

client.login(discordToken);

async function registerCommands() {
  const commands = [
    new SlashCommandBuilder().setName('issue').setDescription('Issue a new license via modal input.'),
    new SlashCommandBuilder().setName('revoke').setDescription('Revoke an existing license by JTI.'),
    new SlashCommandBuilder().setName('status').setDescription('Check license revocation status.'),
  ].map((command) => command.toJSON());

  const rest = new REST({ version: '10' }).setToken(discordToken);
  if (guildId) {
    await rest.put(Routes.applicationGuildCommands(discordClientId, guildId), { body: commands });
    console.log(`Registered slash commands for guild ${guildId}`);
  } else {
    await rest.put(Routes.applicationCommands(discordClientId), { body: commands });
    console.log('Registered global slash commands (may take up to an hour to propagate).');
  }
}

async function handleSlashCommand(interaction) {
  if (interaction.commandName === 'issue') {
    const modal = new ModalBuilder().setCustomId('modal:issue').setTitle('Issue License');
    modal.addComponents(
      new ActionRowBuilder().addComponents(
        new TextInputBuilder()
          .setCustomId('hwid')
          .setLabel('HWID')
          .setStyle(TextInputStyle.Short)
          .setRequired(true)
          .setMaxLength(256),
      ),
      new ActionRowBuilder().addComponents(
        new TextInputBuilder()
          .setCustomId('ttlSeconds')
          .setLabel('TTL (seconds)')
          .setPlaceholder('3600 (between 60 and 5184000)')
          .setStyle(TextInputStyle.Short)
          .setRequired(true),
      ),
      new ActionRowBuilder().addComponents(
        new TextInputBuilder()
          .setCustomId('plan')
          .setLabel('Plan (optional)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false),
      ),
      new ActionRowBuilder().addComponents(
        new TextInputBuilder()
          .setCustomId('note')
          .setLabel('Note (optional)')
          .setStyle(TextInputStyle.Paragraph)
          .setRequired(false)
          .setMaxLength(500),
      ),
    );
    await interaction.showModal(modal);
    return;
  }

  if (interaction.commandName === 'revoke') {
    const modal = new ModalBuilder().setCustomId('modal:revoke').setTitle('Revoke License');
    modal.addComponents(
      new ActionRowBuilder().addComponents(
        new TextInputBuilder()
          .setCustomId('jti')
          .setLabel('License JTI')
          .setStyle(TextInputStyle.Short)
          .setRequired(true)
          .setMaxLength(128),
      ),
    );
    await interaction.showModal(modal);
    return;
  }

  if (interaction.commandName === 'status') {
    const modal = new ModalBuilder().setCustomId('modal:status').setTitle('License Status');
    modal.addComponents(
      new ActionRowBuilder().addComponents(
        new TextInputBuilder()
          .setCustomId('jti')
          .setLabel('License JTI')
          .setStyle(TextInputStyle.Short)
          .setRequired(true)
          .setMaxLength(128),
      ),
    );
    await interaction.showModal(modal);
  }
}

async function handleModalSubmit(interaction) {
  const modalHandlers = {
    'modal:issue': handleIssueModal,
    'modal:revoke': handleRevokeModal,
    'modal:status': handleStatusModal,
  };

  const handler = modalHandlers[interaction.customId];
  if (!handler) {
    await interaction.reply({ content: 'Unknown modal.', ephemeral: true });
    return;
  }

  await handler(interaction);
}

async function handleIssueModal(interaction) {
  await interaction.deferReply({ ephemeral: true });
  const hwid = interaction.fields.getTextInputValue('hwid').trim();
  const ttlInput = interaction.fields.getTextInputValue('ttlSeconds').trim();
  const plan = interaction.fields.getTextInputValue('plan').trim();
  const note = interaction.fields.getTextInputValue('note').trim();

  const ttl = Number.parseInt(ttlInput, 10);
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 5_184_000) {
    await interaction.editReply({ content: 'TTL must be an integer between 60 and 5,184,000 seconds.' });
    return;
  }

  const body = { hwid, ttlSeconds: ttl };
  if (plan) body.plan = plan;
  if (note) body.note = note;

  const response = await callIssuer('/issue', {
    method: 'POST',
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${basicAuth}`,
    },
  });

  if (!response.ok) {
    const reason = await safeReadJson(response);
    await interaction.editReply({ content: `Issue failed (status ${response.status}): ${formatReason(reason)}` });
    return;
  }

  const payload = await response.json();
  const truncatedToken = truncateToken(payload.token);

  tokenCache.set(payload.jti, {
    token: payload.token,
    userId: interaction.user.id,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  const revealButton = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(`reveal:${payload.jti}`)
      .setStyle(ButtonStyle.Secondary)
      .setLabel('Reveal token'),
  );

  const lines = [
    `License issued for **${hwid}**`,
    `JTI: \`${payload.jti}\``,
    `Expires: <t:${payload.exp}:f>`,
    `Token preview: \`${truncatedToken}\``,
    'Use the button below to reveal the full JWT (available for 5 minutes).',
  ];

  await interaction.editReply({ content: lines.join('\n'), components: [revealButton] });
}

async function handleRevokeModal(interaction) {
  await interaction.deferReply({ ephemeral: true });
  const jti = interaction.fields.getTextInputValue('jti').trim();

  const response = await callIssuer('/revoke', {
    method: 'POST',
    body: JSON.stringify({ jti }),
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${basicAuth}`,
    },
  });

  if (!response.ok) {
    const reason = await safeReadJson(response);
    await interaction.editReply({ content: `Revoke failed (status ${response.status}): ${formatReason(reason)}` });
    return;
  }

  tokenCache.delete(jti);
  await interaction.editReply({ content: `License ${jti} revoked (or already revoked).` });
}

async function handleStatusModal(interaction) {
  await interaction.deferReply({ ephemeral: true });
  const jti = interaction.fields.getTextInputValue('jti').trim();

  const response = await callIssuer(`/status/${encodeURIComponent(jti)}`, {
    method: 'GET',
    headers: {
      Authorization: `Basic ${basicAuth}`,
    },
  });

  if (!response.ok) {
    const reason = await safeReadJson(response);
    await interaction.editReply({ content: `Status lookup failed (status ${response.status}): ${formatReason(reason)}` });
    return;
  }

  const payload = await response.json();
  const status = payload.revoked ? 'revoked' : 'active';
  await interaction.editReply({ content: `License ${jti} is ${status}.` });
}

async function handleButton(interaction) {
  if (!interaction.customId.startsWith('reveal:')) {
    await interaction.reply({ content: 'Unknown action.', ephemeral: true });
    return;
  }

  const jti = interaction.customId.slice('reveal:'.length);
  const entry = tokenCache.get(jti);
  if (!entry || entry.expiresAt < Date.now()) {
    tokenCache.delete(jti);
    await interaction.reply({ content: 'Token no longer available. Re-issue to retrieve it again.', ephemeral: true });
    return;
  }

  if (entry.userId !== interaction.user.id) {
    await interaction.reply({ content: 'You are not allowed to view this token.', ephemeral: true });
    return;
  }

  await interaction.reply({
    content: `Full token for ${jti}:\n\n\`\`\`${entry.token}\`\`\``,
    ephemeral: true,
  });
}

async function callIssuer(pathname, init) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  try {
    const url = new URL(pathname, apiBase).toString();
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function safeReadJson(response) {
  try {
    return await response.json();
  } catch (_err) {
    return undefined;
  }
}

function truncateToken(token) {
  if (!token || token.length <= 40) {
    return token || '';
  }
  return `${token.slice(0, 20)}...${token.slice(-8)}`;
}

function normalizeBaseUrl(value) {
  try {
    const parsed = new URL(value);
    if (!parsed.pathname.endsWith('/')) {
      parsed.pathname = `${parsed.pathname}/`;
    }
    return parsed.toString();
  } catch (err) {
    throw new Error(`ISSUER_BASE_URL is invalid: ${err.message}`);
  }
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be set`);
  }
  return value;
}

function formatReason(reason) {
  if (!reason) {
    return 'Unknown error';
  }
  if (typeof reason === 'string') {
    return reason;
  }
  if (typeof reason === 'object' && reason.reason) {
    return reason.reason;
  }
  return JSON.stringify(reason);
}

async function shutdown() {
  console.log('Shutting down Discord bot...');
  try {
    await client.destroy();
  } catch (err) {
    console.error('Error while destroying Discord client:', err);
  }
  await delay(200);
  process.exit(0);
}

setInterval(() => {
  const now = Date.now();
  for (const [jti, entry] of tokenCache.entries()) {
    if (entry.expiresAt <= now) {
      tokenCache.delete(jti);
    }
  }
}, 60_000).unref();
