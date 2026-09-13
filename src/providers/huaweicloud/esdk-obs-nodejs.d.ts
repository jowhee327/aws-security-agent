/**
 * Minimal ambient typing for `esdk-obs-nodejs` (ships no .d.ts).
 * Only the surface Phase 1 scanners use is declared; results are loosely typed.
 */
declare module "esdk-obs-nodejs" {
  export interface ObsCommonMsg {
    Status: number;
    Code?: string;
    Message?: string;
    HostId?: string;
    RequestId?: string;
    Id2?: string;
    Indicator?: string;
  }
  export interface ObsResult<T = Record<string, unknown>> {
    CommonMsg: ObsCommonMsg;
    InterfaceResult?: T;
  }
  export type ObsCallback<T = Record<string, unknown>> = (err: unknown, result: ObsResult<T>) => void;

  export interface ObsClientParams {
    access_key_id?: string;
    secret_access_key?: string;
    security_token?: string;
    server?: string;
    is_secure?: boolean;
    timeout?: number;
    max_retry_count?: number;
    region?: string;
    [k: string]: unknown;
  }

  class ObsClient {
    constructor(params?: ObsClientParams);
    listBuckets(params?: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketAcl(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketPolicy(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketPublicAccessBlock(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketEncryption(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketVersioning(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketReplication(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketLogging(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketTagging(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    getBucketLocation(params: Record<string, unknown>, callback?: ObsCallback): Promise<ObsResult> | void;
    close(): void;
    [method: string]: unknown;
  }
  export default ObsClient;
}
