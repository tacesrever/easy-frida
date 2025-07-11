export declare function getApi(): {
    SSL_get_session: (ssl: NativePointer) => NativePointer;
    SSL_get_client_random: (ssl: NativePointer, outbuf: NativePointer, buflen: number) => number;
    SSL_SESSION_get_id: (session: NativePointer, outlen: NativePointer) => NativePointer;
    SSL_SESSION_get_master_key: (session: NativePointer, outbuf: NativePointer, buflen: number) => number;
    i2d_SSL_SESSION: (session: NativePointer, outbufp: NativePointer) => number;
};
export declare function setSSLKeyListener(listener: (id: ArrayBuffer, key: ArrayBuffer) => any): void;
export declare function setKeyLog(filePath: string): void;
export declare function setSendListener(listener: (buffer: NativePointer, len: number) => void): void;
export declare function setRecvListener(listener: (buffer: NativePointer, len: number) => void): void;
