declare type ActionSource = "strict-dynamic" | "report-sample";
declare type BaseSource = "self" | "unsafe-eval" | "unsafe-hashes" | "unsafe-inline" | "none";
declare type HashAlgorithm = "sha256" | "sha384" | "sha512";
declare type HashWithAlgorithm = `${HashAlgorithm}-${string}`;
declare type NonceWithPrefix = `${"nonce"}-${string}`;
declare type CryptoSource = HashWithAlgorithm | NonceWithPrefix;
declare type FrameSource = HostSource | SchemeSource | "self" | "none";
declare type HostNameScheme = `${string}.${string}` | "localhost";
declare type HostSource = `${HostProtocolSchemes}${HostNameScheme}${PortScheme}`;
declare type HostProtocolSchemes = `${string}://` | "";
declare type HttpDelineator = "/" | "?" | "#" | "\\";
declare type PortScheme = `:${number}` | "" | ":*";
declare type SchemeSource = "http:" | "https:" | "data:" | "mediastream:" | "blob:" | "filesystem:" | "ws:" | "wss:";
declare type Source = HostSource | SchemeSource | CryptoSource | BaseSource;
declare type Sources = Source[];
declare type UriPath = `${HttpDelineator}${string}` | `${HostSource}${HttpDelineator}${string}`;
interface CspDirectives {
    "child-src"?: Sources;
    "default-src"?: Array<Source | ActionSource>;
    "frame-src"?: Sources;
    "worker-src"?: Sources;
    "connect-src"?: Sources;
    "font-src"?: Sources;
    "img-src"?: Sources;
    "manifest-src"?: Sources;
    "media-src"?: Sources;
    "object-src"?: Sources;
    "prefetch-src"?: Sources;
    "script-src"?: Array<Source | ActionSource>;
    "script-src-elem"?: Sources;
    "script-src-attr"?: Sources;
    "style-src"?: Array<Source | ActionSource>;
    "style-src-elem"?: Sources;
    "style-src-attr"?: Sources;
    "base-uri"?: Array<Source | ActionSource>;
    sandbox?: boolean | Array<"allow-downloads-without-user-activation" | "allow-forms" | "allow-modals" | "allow-orientation-lock" | "allow-pointer-lock" | "allow-popups" | "allow-popups-to-escape-sandbox" | "allow-presentation" | "allow-same-origin" | "allow-scripts" | "allow-storage-access-by-user-activation" | "allow-top-navigation" | "allow-top-navigation-by-user-activation">;
    "form-action"?: Array<Source | ActionSource>;
    "frame-ancestors"?: Array<HostSource | SchemeSource | FrameSource>;
    "navigate-to"?: Array<Source | ActionSource>;
    "report-uri"?: UriPath[];
    "report-to"?: string[];
    "require-trusted-types-for"?: Array<"script">;
    "trusted-types"?: Array<"none" | "allow-duplicates" | "*" | string>;
    "upgrade-insecure-requests"?: boolean;
    /** @deprecated */
    "require-sri-for"?: Array<"script" | "style" | "script style">;
    /** @deprecated */
    "block-all-mixed-content"?: boolean;
    /** @deprecated */
    "plugin-types"?: Array<`${string}/${string}` | "none">;
    /** @deprecated */
    referrer?: Array<"no-referrer" | "no-referrer-when-downgrade" | "origin" | "origin-when-cross-origin" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" | "unsafe-url" | "none">;
}
declare type CspDirectivesLenient = Partial<Partial<Record<keyof CspDirectives, string | string[] | boolean>>>;
declare type BooleanDirectiveKeys = "upgrade-insecure-requests" | "block-all-mixed-content" | "sandbox";
declare type BooleanCspDirectives = Pick<CspDirectives, BooleanDirectiveKeys>;
declare type NonBooleanCspDirectives = Omit<CspDirectives, BooleanDirectiveKeys>;
declare type CspFilter = {
    [K in keyof NonBooleanCspDirectives]?: RegExp | NonBooleanCspDirectives[K];
};
declare type ICspCryptoConfig = {
    nonceBits?: number;
    hashAlgorithm?: HashAlgorithm;
};
interface ICspCrypto {
    withConfig(cfg: ICspCryptoConfig): ICspCrypto;
    nonce(): string;
    nonceWithPrefix(): NonceWithPrefix;
    hash(text: string): string;
    hashWithAlgorithm(text: string): HashWithAlgorithm;
}

declare const CSP_HEADER = "content-security-policy";
declare const CSP_HEADER_REPORT_ONLY = "content-security-policy-report-only";
declare const CSP_NONCE_HEADER = "csp-nonce";

declare const arrayifyCspDirectives: (directives: CspDirectives | CspDirectivesLenient) => CspDirectives;
declare const toCspContent: (csp: CspDirectives | CspDirectivesLenient) => string;
declare const fromCspContent: (content: string) => CspDirectives;
declare const extendCsp: (csp?: CspDirectives | CspDirectivesLenient, cspExtension?: CspDirectives | CspDirectivesLenient, mergedDirectiveValues?: "append" | "prepend" | "override") => CspDirectives;
declare const filterCsp: (directives: CspDirectives | CspDirectivesLenient, excludePatterns: CspFilter) => CspDirectives;
declare const cspDirectiveHas: (directives: CspDirectives | CspDirectivesLenient, directive: keyof NonBooleanCspDirectives, patternOrValue: RegExp | string) => boolean;

declare type BuilderConstructorObject = {
    directives?: CspDirectives | CspDirectivesLenient | string;
    reportOnly?: boolean;
};
declare type CspBuilderConstructorParam = BuilderConstructorObject | CspBuilder | string | [string, string];
declare class CspBuilder {
    protected _csp: {
        directives: CspDirectives;
        reportOnly?: boolean;
    };
    constructor(param?: CspBuilderConstructorParam);
    withDirectives(cspDirectives?: CspDirectives | CspDirectivesLenient | string, mergeDirectiveValues?: "append" | "prepend" | "override"): this;
    withoutDirectives(excludeDirectives: (keyof CspDirectives)[]): this;
    withoutDirectiveValues(excludePatterns: CspFilter): this;
    withReportOnly(reportOnly?: boolean): this;
    hasDirective(directive: keyof CspDirectives): boolean;
    hasDirectiveWithPattern(directive: keyof NonBooleanCspDirectives, pattern: RegExp | string): void;
    toHeaderValue(): string;
    toHeaderKeyValue(): ["content-security-policy" | "content-security-policy-report-only", string];
    toString(): string;
    withNonceApplied(nonce: string): this;
    csp(): {
        directives: CspDirectives;
        reportOnly?: boolean;
    };
    withStrictDynamic(hashesOrNonce: HashWithAlgorithm[] | string, fallback?: CspDirectives["script-src"], extendScriptSrc?: boolean): this;
    withStyleHashes(elemHashes?: HashWithAlgorithm[], attrHashes?: HashWithAlgorithm[], removeUnsafeInline?: boolean): this;
    withMergedBuilder(b: CspBuilder): void;
    reset(): void;
    isEmpty(): boolean;
}

export { ActionSource, BaseSource, BooleanCspDirectives, CSP_HEADER, CSP_HEADER_REPORT_ONLY, CSP_NONCE_HEADER, CryptoSource, CspBuilder, CspDirectives, CspDirectivesLenient, CspFilter, FrameSource, HashAlgorithm, HashWithAlgorithm, HostNameScheme, HostProtocolSchemes, HostSource, HttpDelineator, ICspCrypto, ICspCryptoConfig, NonBooleanCspDirectives, NonceWithPrefix, PortScheme, SchemeSource, Source, Sources, UriPath, arrayifyCspDirectives, cspDirectiveHas, extendCsp, filterCsp, fromCspContent, toCspContent };
