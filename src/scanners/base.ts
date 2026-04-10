import { ScanResult, ScanContext } from "../types.js";

export interface Scanner {
  readonly moduleName: string;
  scan(ctx: ScanContext): Promise<ScanResult>;
}
