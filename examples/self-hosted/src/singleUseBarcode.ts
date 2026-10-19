/**
 * Single-use barcode example
 *
 * A Wallet pass barcode is static, so a screenshot or a forwarded
 * copy shows exactly the same code as the original. This example
 * puts an opaque, single-use token in the barcode instead of an
 * order number or a name, and checks it at the door so only the
 * first scan is admitted.
 *
 * The token is issued and spent through the AffixIO verification
 * API (https://api.affix-io.com/openapi.json). Any service with
 * an atomic "mark as used" operation fits the same shape: the
 * pass only carries the token, the door asks the service.
 *
 * Set AFFIXIO_API_KEY in the environment before running.
 *
 * GET  /singleUse/:modelName  .pkpass with a single-use QR code
 * POST /singleUse/scan        body { "message": "<barcode text>" }
 *                             200 { admitted: true }
 *                             409 { admitted: false, reason: "already_used" }
 *
 * Notes:
 * - The door needs a network connection: spending the token is an
 *   online operation, which is what makes a second scan fail.
 * - No personal data goes into the barcode or to the API. The order
 *   reference is hashed before it leaves this server.
 */

import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PKPass } from "passkit-generator";
import { app } from "./webserver.js";
import { getCertificates } from "./shared.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const API_BASE = process.env.AFFIXIO_API_BASE || "https://api.affix-io.com";
const GATE_ID = process.env.AFFIXIO_GATE_ID || "main-door";
const CIRCUIT_ID = "simple_yesno";

/** Hashes any text into a 31 byte hex value accepted by the API as a field. */
function toField(value: string): string {
	return "0x" + createHash("sha256").update(value).digest("hex").slice(0, 62);
}

async function affixio(endpoint: string, body: unknown) {
	const apiKey = process.env.AFFIXIO_API_KEY;

	if (!apiKey) {
		throw new Error("AFFIXIO_API_KEY is not set");
	}

	const response = await fetch(`${API_BASE}${endpoint}`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${apiKey}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify(body),
	});

	return {
		ok: response.ok,
		status: response.status,
		data: (await response.json()) as Record<string, any>,
	};
}

/**
 * Creates a single-use proof for one ticket and wraps it in a
 * short opaque token that is safe to print in a barcode.
 */
async function issueEntryToken(serialNumber: string, validForSeconds: number) {
	const now = Math.floor(Date.now() / 1000);

	const proof = await affixio(`/v1/circuits/${CIRCUIT_ID}/prove`, {
		credential: {
			schema_id: toField("event-ticket.v1"),
			issuer_id: "box-office",
			issuer_pubkey_hash: toField("box-office"),
			credential_id: toField(serialNumber),
			claim_value: "valid-ticket",
			valid_from: now - 60,
			valid_until: now + validForSeconds,
		},
		context: {
			secret: "0x" + randomBytes(31).toString("hex"),
			context_id: toField(GATE_ID),
		},
	});

	if (!proof.ok || proof.data.decision !== "yes") {
		throw new Error(
			`Could not create proof: ${JSON.stringify(proof.data)}`,
		);
	}

	const link = await affixio("/v1/link/issue", {
		proof_digest: proof.data.proof_digest,
		proof_ref: proof.data.proof_id,
		circuit_id: CIRCUIT_ID,
		gate_id: GATE_ID,
		ttl_seconds: validForSeconds,
	});

	if (!link.ok || !link.data.token) {
		throw new Error(`Could not issue token: ${JSON.stringify(link.data)}`);
	}

	return link.data.token as string;
}

app.route("/singleUse/:modelName").get(async (request, response) => {
	const passName =
		request.params.modelName +
		"_" +
		new Date().toISOString().split("T")[0].replace(/-/gi, "");

	try {
		const certificates = await getCertificates();
		const serialNumber = randomBytes(8).toString("hex");

		// Valid for 24 hours. Use the end time of the event in real usage.
		const token = await issueEntryToken(serialNumber, 24 * 60 * 60);

		const pass = await PKPass.from(
			{
				model: path.resolve(
					__dirname,
					`../../models/${request.params.modelName}`,
				),
				certificates: {
					wwdr: certificates.wwdr,
					signerCert: certificates.signerCert,
					signerKey: certificates.signerKey,
					signerKeyPassphrase: certificates.signerKeyPassphrase,
				},
			},
			{ ...(request.query || {}), serialNumber },
		);

		pass.setBarcodes({
			message: token,
			format: "PKBarcodeFormatQR",
			messageEncoding: "iso-8859-1",
			altText: "Single entry",
		});

		if (pass.type === "boardingPass" && !pass.transitType) {
			// Just to not make crash the creation if we use a boardingPass
			pass.transitType = "PKTransitTypeAir";
		}

		const stream = pass.getAsStream();

		response.set({
			"Content-type": pass.mimeType,
			"Content-disposition": `attachment; filename=${passName}.pkpass`,
		});

		stream.pipe(response);
	} catch (err) {
		console.log(err);

		response.set({
			"Content-type": "text/html",
		});

		response.send(err.message);
	}
});

/**
 * Door side. A scanner app posts the barcode text it read.
 * The first scan spends the proof, every later scan gets 409.
 */
app.route("/singleUse/scan").post(async (request, response) => {
	const message = request.body?.message;

	if (typeof message !== "string" || !/^[a-f0-9]{16,64}$/i.test(message)) {
		response.status(400).json({ admitted: false, reason: "bad_barcode" });
		return;
	}

	try {
		const presented = await affixio("/v1/link/verify", { token: message });

		if (!presented.ok || presented.data.allow !== true) {
			response.status(403).json({
				admitted: false,
				reason: presented.data.reason_code || "unknown_or_expired",
			});
			return;
		}

		const spend = await affixio("/v1/gate/verify", {
			circuit_id: presented.data.carrier.circuit_id,
			proof: presented.data.carrier.proof_ref,
			gate_id: GATE_ID,
			mode: "consume",
		});

		if (spend.status === 409) {
			response
				.status(409)
				.json({ admitted: false, reason: "already_used" });
			return;
		}

		if (!spend.ok || spend.data.allow !== true) {
			response.status(403).json({
				admitted: false,
				reason: spend.data.reason_code || spend.data.error || "refused",
			});
			return;
		}

		response.json({ admitted: true, receipt: spend.data.receipt_id });
	} catch (err) {
		console.log(err);
		response.status(502).json({ admitted: false, reason: "check_failed" });
	}
});
