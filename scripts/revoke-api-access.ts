#!/usr/bin/env -S tsx

import process from "node:process";

type CloudflareToken = {
	id: string;
	name?: string;
	status?: string;
	created_on?: string;
	expires_on?: string;
	last_used_at?: string;
};

type ApiTokenResponse = {
	success: boolean;
	error?: Array<{ message?: string }>;
	result: CloudflareToken[];
};

const usage = `Usage:
  pnpm run script:revoke-api-access -- --apply --keep <token-id-or-name>
  pnpm run script:revoke-api-access -- --apply --keep "my-token" --keep "other-safe-token"

Environment variables:
  CLOUDFLARE_API_TOKEN      Required Cloudflare API token with permission to manage tokens
  CLOUDFLARE_ACCOUNT_ID     Required when revoking account-scoped API tokens
  CLOUDFLARE_KEEP_TOKENS    Optional comma-separated list of token IDs or names to preserve

Flags:
  --apply                  Actually revoke tokens instead of just listing them
  --keep <value>           Keep a token by ID or name (repeatable)
  --dry-run                Print what would happen without revoking anything
  --help                   Show this message

This script revokes all account-scoped and user-scoped Cloudflare API tokens except those
explicitly kept. It is intentionally safe by default: nothing is deleted unless --apply is set.`;

function isTruthy(value: string | undefined): boolean {
	return value === "1" || value === "true" || value === "yes";
}

function splitCsv(value: string | undefined): string[] {
	if (!value) return [];
	return value
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean);
}

function parseArgs(argv: string[]) {
	const result = {
		apply: false,
		dryRun: false,
		keep: new Set<string>(),
		help: false,
	};

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];

		switch (arg) {
			case "--apply":
			case "-a":
				result.apply = true;
				break;
			case "--dry-run":
				result.dryRun = true;
				break;
			case "--help":
			case "-h":
				result.help = true;
				break;
			case "--keep": {
				const next = argv[i + 1];
				if (!next || next.startsWith("-")) {
					throw new Error("Missing value after --keep");
				}
				result.keep.add(next);
				i += 1;
				break;
			}
			default:
				if (arg.startsWith("--keep=")) {
					result.keep.add(arg.slice("--keep=".length));
				} else {
					throw new Error(`Unknown argument: ${arg}`);
				}
		}
	}

	for (const token of splitCsv(process.env.CLOUDFLARE_KEEP_TOKENS)) {
		result.keep.add(token);
	}

	if (result.dryRun && result.apply) {
		result.dryRun = false;
	}

	return result;
}

function normalizeTokenMatch(value: string): string {
	return value.trim().toLowerCase();
}

function isAllowed(token: CloudflareToken, keep: Set<string>): boolean {
	const tokenId = normalizeTokenMatch(token.id);
	const tokenName = normalizeTokenMatch(token.name ?? "");

	for (const candidate of keep) {
		const normalized = normalizeTokenMatch(candidate);
		if (!normalized) continue;
		if (tokenId === normalized || tokenName === normalized) {
			return true;
		}
	}

	return false;
}

async function cloudflareRequest<T>(path: string, init?: RequestInit): Promise<T> {
	const token = process.env.CLOUDFLARE_API_TOKEN;
	if (!token) {
		throw new Error(
			"Missing CLOUDFLARE_API_TOKEN. Export a token with sufficient permissions to list and revoke API tokens.",
		);
	}

	const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
		...init,
		headers: {
			Authorization: `Bearer ${token}`,
			"Content-Type": "application/json",
			...(init?.headers ?? {}),
		},
	});

	const payload = (await response.json()) as {
		success?: boolean;
		error?: Array<{ message?: string }>;
		result?: T;
	};

	if (!response.ok || payload.success === false) {
		const message = payload.error?.[0]?.message ?? `HTTP ${response.status}`;
		throw new Error(`Cloudflare API request failed for ${path}: ${message}`);
	}

	return payload.result as T;
}

async function listUserTokens(): Promise<CloudflareToken[]> {
	return await cloudflareRequest<CloudflareToken[]>("/user/tokens?per_page=100");
}

async function listAccountTokens(accountId: string): Promise<CloudflareToken[]> {
	return await cloudflareRequest<CloudflareToken[]>(
		`/accounts/${accountId}/api/tokens?per_page=100`,
	);
}

async function revokeToken(token: CloudflareToken, scope: "user" | "account", accountId?: string) {
	const endpoint =
		scope === "user"
			? `/user/tokens/${token.id}`
			: `/accounts/${accountId}/api/tokens/${token.id}`;

	await cloudflareRequest<unknown>(endpoint, {
		method: "DELETE",
	});
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	if (args.help) {
		console.log(usage);
		process.exit(0);
	}

	const keep = args.keep;
	const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;

	if (!accountId) {
		console.warn(
			"CLOUDFLARE_ACCOUNT_ID is not set. Only user-scoped tokens will be evaluated.",
		);
	}

	const userTokens = await listUserTokens();
	const accountTokens = accountId ? await listAccountTokens(accountId) : [];
	const allTokens = [
		...userTokens.map((token) => ({ ...token, scope: "user" as const })),
		...accountTokens.map((token) => ({ ...token, scope: "account" as const })),
	];

	const revokeCandidates = allTokens.filter(
		(token) => !isAllowed(token, keep) && (token.status ?? "active") !== "revoked",
	);

	if (revokeCandidates.length === 0) {
		console.log("No active tokens require revocation.");
		return;
	}

	console.log(
		`Found ${revokeCandidates.length} token(s) to revoke (excluding ${keep.size} keep-listed token(s)).`,
	);

	for (const token of revokeCandidates) {
		const scope = token.scope;
		const line =
			`- ${scope}: ${token.name ?? token.id} (${token.id})` +
			`${token.expires_on ? `, expires ${token.expires_on}` : ""}`;
		console.log(line);
	}

	if (args.apply || args.dryRun) {
		if (args.dryRun) {
			console.log("Dry run only. No tokens were revoked.");
			return;
		}

		for (const token of revokeCandidates) {
			const scope = token.scope;
			const account = scope === "account" ? accountId : undefined;
			console.log(`Revoking ${token.name ?? token.id} (${token.id})...`);
			await revokeToken(token, scope, account);
			console.log("OK");
		}

		console.log("Revocation complete.");
	}
}

main().catch((error) => {
	console.error("Error:", error instanceof Error ? error.message : error);
	process.exit(1);
});
