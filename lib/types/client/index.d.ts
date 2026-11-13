/**
 * Codex Security workbench — browser half of dsh-codex-security.
 *
 * Registers one settings.section that renders the scan workbench against the
 * plugin's HTTP routes (/plugins/codex-security). Every response path guards
 * HTTP failures and non-JSON bodies with an inline error banner; every effect
 * owns an AbortController and aborts on unmount, and no state is written after
 * unmount. Only React is imported (the DSH web client module loader maps
 * 'react' and 'react/jsx-runtime').
 */
import * as React from 'react';
export declare const name = "dsh-codex-security";
export declare const inject: string[];
interface SlotsApi {
    inject(name: string, callback: () => () => void): void;
    register(options: {
        name: string;
        id: string;
        order: number;
        label: string;
    }, component: React.ComponentType): () => void;
}
export declare function apply(ctx: {
    slots: SlotsApi;
}): void;
export {};
