
export class PcapWriter {
  chunks: Uint8Array[] = [];

  constructor() {
    this.writeGlobalHeader();
  }

  private writeGlobalHeader() {
    const buffer = new ArrayBuffer(24);
    const view = new DataView(buffer);

    // Magic Number (0xa1b2c3d4)
    view.setUint32(0, 0xa1b2c3d4, true); // Little endian usually safe for PCAP
    // Version Major (2)
    view.setUint16(4, 2, true);
    // Version Minor (4)
    view.setUint16(6, 4, true);
    // ThisZone (0)
    view.setInt32(8, 0, true);
    // SigFigs (0)
    view.setUint32(12, 0, true);
    // SnapLen (65535)
    view.setUint32(16, 65535, true);
    // Network (1 = Ethernet) - assuming Ethernet for now as generic
    view.setUint32(20, 1, true);

    this.chunks.push(new Uint8Array(buffer));
  }

  writePacket(hexData: string, timestamp?: number) {
    // Hex to Uint8Array
    const len = hexData.length / 2;
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      buffer[i] = parseInt(hexData.substring(i * 2, i * 2 + 2), 16);
    }

    const headerBuf = new ArrayBuffer(16);
    const view = new DataView(headerBuf);

    let sec = 0;
    let usec = 0;

    if (timestamp) {
        sec = Math.floor(timestamp);
        usec = Math.floor((timestamp - sec) * 1000000);
    } else {
        const now = Date.now();
        sec = Math.floor(now / 1000);
        usec = (now % 1000) * 1000;
    }

    view.setUint32(0, sec, true);
    view.setUint32(4, usec, true);
    view.setUint32(8, len, true); // Incl Len
    view.setUint32(12, len, true); // Orig Len (assuming no truncation)

    this.chunks.push(new Uint8Array(headerBuf));
    this.chunks.push(buffer);
  }

  getUint8Array(): Uint8Array {
    const totalLength = this.chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  getBlob(): Blob {
    return new Blob(this.chunks, { type: 'application/vnd.tcpdump.pcap' });
  }
}
