'use strict';

/**
 * Forensic evidence integrity chaincode.
 * Provides immutable dual-hash storage for disk images and a queryable audit trail.
 * Invoked as the final, non-blocking step after AI analysis completes.
 */

const { Contract } = require('fabric-contract-api');

class ForensicContract extends Contract {

    /**
     * Persist acquisition and system SHA-256 hashes for a disk image under evidenceId.
     * Rejects duplicates so an existing evidence record cannot be overwritten.
     */
    async StoreEvidence(ctx, evidenceId, acquisitionHash, systemHash, imageName, caseId, timestamp) {
        const exists = await ctx.stub.getState(evidenceId);
        if (exists && exists.length > 0) {
            throw new Error(`Evidence ${evidenceId} already exists`);
        }

        const evidence = {
            evidenceId,
            acquisitionHash,
            systemHash,
            imageName,
            caseId,
            timestamp,
            submittedBy: ctx.clientIdentity.getMSPID(),
            docType: 'evidence',
        };

        await ctx.stub.putState(evidenceId, Buffer.from(JSON.stringify(evidence)));
        return JSON.stringify(evidence);
    }

    /**
     * Compare a recomputed hash to the sealed on-chain systemHash for integrity verification.
     * Returns isValid/tampered plus the stored and provided hash values.
     */
    async ValidateEvidence(ctx, evidenceId, currentHash) {
        const raw = await ctx.stub.getState(evidenceId);
        if (!raw || raw.length === 0) {
            throw new Error(`Evidence ${evidenceId} does not exist`);
        }

        const stored = JSON.parse(raw.toString());
        const isValid = stored.systemHash === currentHash;
        const result = {
            evidenceId,
            isValid,
            tampered: !isValid,
            storedHash: stored.systemHash,
            providedHash: currentHash,
            validatedAt: new Date().toISOString(),
        };
        return JSON.stringify(result);
    }

    /**
     * Read the sealed evidence record written by StoreEvidence.
     * Returns JSON null string when the evidenceId is not on the ledger.
     */
    async GetEvidence(ctx, evidenceId) {
        const data = await ctx.stub.getState(evidenceId);
        if (!data || data.length === 0) {
            return JSON.stringify(null);
        }
        return data.toString('utf8');
    }

    /**
     * Append an immutable analyst or system action to the audit log for an evidenceId.
     * Uses composite key log+[evidenceId,timestamp] for efficient range queries.
     */
    async LogAnalystAction(ctx, evidenceId, analystId, action, details, timestamp) {
        const key = ctx.stub.createCompositeKey('log', [evidenceId, timestamp]);
        const entry = {
            evidenceId,
            analystId,
            action,
            details,
            timestamp,
            docType: 'auditlog',
        };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(entry)));
        return JSON.stringify(entry);
    }

    /**
     * Return all audit log entries for an evidenceId, ordered oldest first.
     */
    async GetAuditTrail(ctx, evidenceId) {
        const iterator = await ctx.stub.getStateByPartialCompositeKey('log', [evidenceId]);
        const entries = [];
        let result = await iterator.next();
        while (!result.done) {
            if (result.value && result.value.value) {
                const str = result.value.value.toString('utf8');
                if (str) {
                    entries.push(JSON.parse(str));
                }
            }
            result = await iterator.next();
        }
        await iterator.close();
        entries.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
        return JSON.stringify(entries);
    }
}

module.exports = ForensicContract;
