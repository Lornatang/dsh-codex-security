type ArtifactKind = 'findings' | 'coverage' | 'scan-manifest';
export declare function compileToolArguments(schema: object): (value: unknown) => void;
/** Validate the exact documents shipped by this package before publishing a seal. */
export declare function assertArtifactContract(kind: ArtifactKind, value: unknown): void;
export {};
