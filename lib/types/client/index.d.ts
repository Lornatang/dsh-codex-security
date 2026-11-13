import * as React from 'react';
export declare const name = "@lornatang/dsh-codex-security";
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
