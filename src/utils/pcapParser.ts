
export interface PcapPacket {
  header: {
    ts_sec: number;
    ts_usec: number;
    incl_len: number;
    orig_len: number;
  };
  data: Uint8Array;
}

export class PcapParser {
  private buffer: ArrayBuffer;
  private view: DataView;
  private offset: number = 0;
  private littleEndian: boolean = true;

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
  }

  parse(): PcapPacket[] {
    this.offset = 0;
    const packets: PcapPacket[] = [];

    // Parse Global Header (24 bytes)
    if (this.view.byteLength < 24) {
      throw new Error("File too short to be a PCAP");
    }

    const magic = this.view.getUint32(0, true);
    if (magic === 0xa1b2c3d4) {
      this.littleEndian = true;
    } else if (magic === 0xd4c3b2a1) {
      this.littleEndian = false;
    } else {
      // Support nanosecond pcap? (0xa1b23c4d) - usually same structure just different timestamp precision
      if (magic === 0xa1b23c4d) {
          this.littleEndian = true;
      } else if (magic === 0x4d3cb2a1) {
          this.littleEndian = false;
      } else {
          throw new Error(`Unknown Global Header Magic Number: ${magic.toString(16)}`);
      }
    }

    // Skip rest of global header (version, timezone, sigfigs, snaplen, network)
    // Major (2), Minor (2), Zone (4), SigFigs (4), SnapLen (4), Network (4)
    this.offset += 24;

    while (this.offset < this.view.byteLength) {
      if (this.offset + 16 > this.view.byteLength) break;

      // Packet Header (16 bytes)
      const ts_sec = this.view.getUint32(this.offset, this.littleEndian);
      const ts_usec = this.view.getUint32(this.offset + 4, this.littleEndian);
      const incl_len = this.view.getUint32(this.offset + 8, this.littleEndian);
      const orig_len = this.view.getUint32(this.offset + 12, this.littleEndian);

      this.offset += 16;

      if (this.offset + incl_len > this.view.byteLength) break;

      const data = new Uint8Array(this.buffer, this.offset, incl_len);
      this.offset += incl_len;

      packets.push({
        header: { ts_sec, ts_usec, incl_len, orig_len },
        data: new Uint8Array(data) // Copy it to avoid referencing the huge buffer?
      });
    }

    return packets;
  }
}
