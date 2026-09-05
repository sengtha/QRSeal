// Minimal typings for the two browser-only dependencies the demo bundles.
// Neither ships types that this project wants to depend on; the surface used
// here is small enough to declare.

declare module 'qrcode' {
  export interface QRCodeToCanvasOptions {
    errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
    margin?: number;
    width?: number;
  }
  export interface QRCodeCreateOptions {
    errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
  }
  export interface QRCodeSymbol {
    version: number;
    modules: { size: number };
  }
  const QRCode: {
    toCanvas(canvas: HTMLCanvasElement, text: string, options?: QRCodeToCanvasOptions): Promise<void>;
    create(text: string, options?: QRCodeCreateOptions): QRCodeSymbol;
  };
  export default QRCode;
}

declare module 'jsqr' {
  export interface QRCodeResult {
    data: string;
  }
  export interface JsQrOptions {
    inversionAttempts?: 'dontInvert' | 'onlyInvert' | 'attemptBoth' | 'invertFirst';
  }
  export default function jsQR(
    data: Uint8ClampedArray,
    width: number,
    height: number,
    options?: JsQrOptions,
  ): QRCodeResult | null;
}
