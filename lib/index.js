import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PLUGIN_NAME, PACKAGE_NAME, VERSION } from './constants.js';
import { Config } from './config.js';
import { SecurityService } from './service.js';
import { bindRoutes } from './routes.js';
import { registerSecurityTools } from './tools.js';
export const name = PLUGIN_NAME;
export const inject = ['tools', 'skills'];
export { Config };
export const version = VERSION;
export const packageName = PACKAGE_NAME;
export { SecurityService };
function parseFrontmatter(text) {
    if (!text.startsWith('---'))
        return { frontmatter: {}, body: text };
    const end = text.indexOf('\n---', 3);
    if (end < 0)
        return { frontmatter: {}, body: text };
    const raw = text.slice(3, end).trim();
    const body = text.slice(text.indexOf('\n', end + 1) + 1);
    const frontmatter = {};
    let currentKey;
    for (const line of raw.split(/\r?\n/)) {
        const match = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
        if (match) {
            currentKey = match[1];
            const value = (match[2] ?? '').trim().replace(/^['"]|['"]$/g, '');
            if (value.length > 0) {
                if (currentKey === 'name')
                    frontmatter.name = value;
                else if (currentKey === 'description')
                    frontmatter.description = value;
                else if (currentKey === 'whenToUse' || currentKey === 'when_to_use' || currentKey === 'when-to-use')
                    frontmatter.whenToUse = value;
            }
            continue;
        }
        if (currentKey === 'description' && line.trim().length > 0 && frontmatter.description)
            frontmatter.description = (frontmatter.description + ' ' + line.trim()).trim();
    }
    return { frontmatter, body };
}
export function loadBundledSkills(packageRoot) {
    const root = join(packageRoot, 'skills');
    const skills = [];
    let entries = [];
    try {
        entries = readdirSync(root);
    }
    catch {
        return skills;
    }
    for (const entry of entries) {
        const directory = join(root, entry);
        let isDirectory = false;
        try {
            isDirectory = statSync(directory).isDirectory();
        }
        catch {
            continue;
        }
        if (!isDirectory)
            continue;
        const file = join(directory, 'SKILL.md');
        let text = '';
        try {
            text = readFileSync(file, 'utf8');
        }
        catch {
            continue;
        }
        const { frontmatter, body } = parseFrontmatter(text);
        const skillName = frontmatter.name ?? entry;
        if (!/^[a-z0-9][a-z0-9-]*$/.test(skillName))
            continue;
        const description = frontmatter.description;
        if (!description)
            continue;
        skills.push({
            name: skillName,
            description,
            source: 'bundled',
            ...(frontmatter.whenToUse ? { whenToUse: frontmatter.whenToUse } : {}),
            content: body,
            path: file,
            resourceBase: { kind: 'directory', path: directory },
            invocation: { modelInvocable: true, userInvocable: true },
            metadata: { plugin: PACKAGE_NAME },
        });
    }
    return skills;
}
function registerSkills(ctx, packageRoot) {
    const disposers = [];
    for (const skill of loadBundledSkills(packageRoot)) {
        try {
            disposers.push(ctx.skills.register(skill));
        }
        catch (error) {
            ctx.logger.warn('codex-security: failed to register skill ' + skill.name + ': ' + String(error));
        }
    }
    ctx.logger.info('codex-security: registered ' + disposers.length + ' skills');
    return () => { for (const dispose of disposers) {
        try {
            dispose();
        }
        catch { /* disposed */ }
    } };
}
export function apply(ctx, config = {}) {
    const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
    const service = new SecurityService(ctx, { config });
    ctx.effect(() => registerSecurityTools(ctx, service), 'codex-security: tools');
    ctx.effect(() => registerSkills(ctx, packageRoot), 'codex-security: skills');
    ctx.effect(() => bindRoutes(ctx, service), 'codex-security: routes');
    ctx.logger.info('codex-security: ready (state dir will resolve on first scan)');
}
export default { name, inject, Config, apply };
