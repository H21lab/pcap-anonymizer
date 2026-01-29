
import { AnonymizedField } from './anonymizer';
import { rewriteFrame } from '../utils/hexUtils';
import { PcapWriter } from '../utils/pcapWriter';

type RawFieldVal = [string, number, number, number, number];

interface RawItem {
  key: string;
  val: RawFieldVal;
  fieldName: string;
}

function* rawFlatCollector(obj: any, parentKey: string = ''): Generator<RawItem> {
  if (typeof obj === 'object' && obj !== null) {
    for (const k in obj) {
      const v = obj[k];
      if (k.endsWith('_raw')) {
        let name = k;
        if (name.includes(' == ')) name = name.split(' == ')[0] + '_raw';
        if (name.includes(' eq ')) name = name.split(' eq ')[0] + '_raw';
        // Only prepend parentKey if name doesn't already contain dots (not a full filter path)
        // Wireshark field filters already include the full protocol hierarchy with dots
        if (parentKey && !name.includes('.') && !name.startsWith(parentKey)) name = parentKey + '.' + name;

        if (Array.isArray(v) && v.length > 0 && Array.isArray(v[0])) {
            for (const subV of v) yield { key: k, val: subV as RawFieldVal, fieldName: name };
        } else if (Array.isArray(v) && v.length >= 3 && typeof v[0] === 'string' && typeof v[1] === 'number') {
            yield { key: k, val: v as RawFieldVal, fieldName: name };
        }
      } else if (typeof v === 'object' && v !== null) {
        if (Array.isArray(v)) {
            for (const item of v) {
                if (typeof item === 'object') {
                    for (const subItem of rawFlatCollector(item, k)) yield subItem;
                }
            }
        } else {
            for (const subItem of rawFlatCollector(v, k)) yield subItem;
        }
      }
    }
  }
}

export interface AnonymizeConfig {
    mask: string[];
    anonymize: string[];
    salt?: string;
}

export function processPacketsInternal(packets: any[], config: AnonymizeConfig): PcapWriter {
  const writer = new PcapWriter();
  const salt = config.salt || Math.random().toString(36).substring(2, 15);
  const anonymizeMap: { [key: string]: AnonymizedField } = {};
  
  config.mask.forEach(m => {
    const af = new AnonymizedField(m, 0);
    anonymizeMap[af.field] = af;
  });
  config.anonymize.forEach(a => {
    const af = new AnonymizedField(a, 1);
    anonymizeMap[af.field] = af;
  });

  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i];
    const layers = packet._source?.layers || {};
    
    let frameRaw = '';
    if (layers['frame_raw']) {
        const fr = layers['frame_raw'];
        if (Array.isArray(fr[0])) {
            frameRaw = fr.map((s: any) => s[0]).join('');
        } else {
            frameRaw = String(fr[0]);
        }
    }
    if (!frameRaw) continue;

    let frameMmask = '0'.repeat(frameRaw.length);
    const frameTime = layers['frame'] ? parseFloat(layers['frame']['frame.time_epoch']) : undefined;

    const allRaw = Array.from(rawFlatCollector(layers));
    const items = allRaw
        .filter(item => item.key !== 'frame_raw')
        .map(item => ({
            h: item.val[0],
            p: item.val[1] * 2,
            l: item.val[2] * 2,
            b: item.val[3] !== undefined ? item.val[3] : 0,
            t: item.val[4] !== undefined ? item.val[4] : 0,
            name: item.fieldName
        }));

    // SORTING: Longest first
    items.sort((a, b) => {
        if (a.p !== b.p) {
            return a.p - b.p;
        }
        return b.l - a.l;
    });

    for (const item of items) {
        let h = item.h;
        let hMask = 'f'.repeat(h.length);

        if (anonymizeMap[item.name]) {
            const [newH, newMask] = anonymizeMap[item.name].anonymize(h, item.t, salt);
            h = newH;
            hMask = newMask;
        }

        const s1 = frameRaw;
        frameRaw = rewriteFrame(frameRaw, h, item.p, item.l, item.b, item.t, frameMmask);

        if (anonymizeMap[item.name] || s1 !== frameRaw) {
             frameMmask = rewriteFrame(frameMmask, hMask, item.p, item.l, item.b, item.t);
        }
    }

    writer.writePacket(frameRaw, frameTime);
  }

  return writer;
}

export function processPackets(packets: any[], config: AnonymizeConfig): Blob {
  return processPacketsInternal(packets, config).getBlob();
}

export function processPacketsToBuffer(packets: any[], config: AnonymizeConfig): Uint8Array {
  return processPacketsInternal(packets, config).getUint8Array();
}
