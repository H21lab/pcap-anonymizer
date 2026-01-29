
import { PcapPacket } from '../utils/pcapParser';

// Helper to convert Uint8Array to Hex String
function toHex(buffer: Uint8Array): string {
  return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

export class SimpleDissector {
  
  dissect(packets: PcapPacket[]): any[] {
    return packets.map(packet => {
      const layers: any = {};
      const data = packet.data;
      const fullHex = toHex(data);
      
      // Frame Layer
      layers['frame'] = {
        'frame.time_epoch': (packet.header.ts_sec + packet.header.ts_usec / 1000000).toString(),
        'frame.len': packet.header.incl_len
      };
      // [hex, pos, len, mask, type]
      // Pos is 0 for frame
      layers['frame_raw'] = [fullHex, 0, data.length, 0, 1];

      let offset = 0;

      // --- ETHERNET (14 bytes) ---
      if (data.length >= 14) {
        const ethDst = data.slice(0, 6);
        const ethSrc = data.slice(6, 12);
        const ethType = (data[12] << 8) | data[13];
        
        layers['eth'] = {
          'eth.dst': toHex(ethDst),
          'eth.dst_raw': [toHex(ethDst), 0, 6, 0, 1],
          'eth.src': toHex(ethSrc),
          'eth.src_raw': [toHex(ethSrc), 6, 6, 0, 1],
          'eth.type': '0x' + ethType.toString(16)
        };
        
        offset += 14;

        // --- IPv4 (EtherType 0x0800) ---
        if (ethType === 0x0800 && data.length >= offset + 20) {
          const ipVerIhl = data[offset];
          const ihl = (ipVerIhl & 0x0F) * 4;
          const proto = data[offset + 9];
          
          const ipSrc = data.slice(offset + 12, offset + 16);
          const ipDst = data.slice(offset + 16, offset + 20);

          layers['ip'] = {
            'ip.version': (ipVerIhl >> 4),
            'ip.hdr_len': ihl,
            'ip.proto': proto,
            'ip.src': ipSrc.join('.'),
            'ip.src_raw': [toHex(ipSrc), offset + 12, 4, 0, 1],
            'ip.dst': ipDst.join('.'),
            'ip.dst_raw': [toHex(ipDst), offset + 16, 4, 0, 1]
          };

          offset += ihl;

          // --- TCP (Proto 6) ---
          if (proto === 6 && data.length >= offset + 20) {
             const srcPort = (data[offset] << 8) | data[offset + 1];
             const dstPort = (data[offset + 2] << 8) | data[offset + 3];
             const seq = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];

             layers['tcp'] = {
               'tcp.srcport': srcPort,
               'tcp.srcport_raw': [toHex(data.slice(offset, offset+2)), offset, 2, 0, 1],
               'tcp.dstport': dstPort,
               'tcp.dstport_raw': [toHex(data.slice(offset+2, offset+4)), offset+2, 2, 0, 1],
               'tcp.seq': seq
             };
          } 
          // --- UDP (Proto 17) ---
          else if (proto === 17 && data.length >= offset + 8) {
             const srcPort = (data[offset] << 8) | data[offset + 1];
             const dstPort = (data[offset + 2] << 8) | data[offset + 3];
             const length = (data[offset + 4] << 8) | data[offset + 5];

             layers['udp'] = {
                'udp.srcport': srcPort,
                'udp.srcport_raw': [toHex(data.slice(offset, offset+2)), offset, 2, 0, 1],
                'udp.dstport': dstPort,
                'udp.dstport_raw': [toHex(data.slice(offset+2, offset+4)), offset+2, 2, 0, 1],
                'udp.length': length
             };
          }
        }
      }

      // Return Wrapped Structure
      return {
        _source: {
          layers: layers
        }
      };
    });
  }
}
