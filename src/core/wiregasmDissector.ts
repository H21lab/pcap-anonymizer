
// @ts-ignore
import loadWiregasm from '@goodtools/wiregasm/dist/wiregasm';
import { PcapParser, PcapPacket } from '../utils/pcapParser';

export class WiregasmDissector {
  private wg: any = null;
  private currentSess: any = null;
  private currentPackets: PcapPacket[] = [];

  async init(locateFilePath?: (path: string, prefix: string) => string) {
    if (this.wg) return;
    
    const locateFile = locateFilePath || ((path: string, prefix: string) => {
      if (path.endsWith(".data")) return "./wiregasm.data";
      if (path.endsWith(".wasm")) return "./wiregasm.wasm";
      return prefix + path;
    });

    this.wg = await loadWiregasm({ locateFile });
    this.wg.init();
    if (this.wg.conf_all_protocols_enabled) this.wg.conf_all_protocols_enabled(true);
    if (this.wg.init_epan) this.wg.init_epan();
  }

  private getProp(obj: any, name: string) {
      if (!obj) return undefined;
      if (typeof obj[name] === 'function') {
          try { return obj[name](); } catch(e) { return undefined; }
      }
      return obj[name];
  }

  private cleanFilter(filter: string): string {
      if (!filter) return "";
      let cleaned = filter;
      if (cleaned.includes(' == ')) cleaned = cleaned.split(' == ')[0];
      if (cleaned.includes(' eq ')) cleaned = cleaned.split(' eq ')[0];
      return cleaned.trim();
  }

  async dissect(file: File, filter: string = ""): Promise<any[]> {
    if (!this.wg) await this.init();
    const arrayBuffer = await file.arrayBuffer();
    if (this.currentSess) {
        this.currentSess.delete();
        this.currentSess = null;
    }
    try {
        const parser = new PcapParser(arrayBuffer);
        this.currentPackets = parser.parse();
    } catch (e) {
        console.warn("PcapParser failed", e);
        this.currentPackets = [];
    }
    const data = new Uint8Array(arrayBuffer);
    const filename = "/uploads/" + file.name;
    try {
        if (!this.wg.FS.analyzePath("/uploads").exists) this.wg.FS.mkdir("/uploads");
    } catch (e) { }
    this.wg.FS.writeFile(filename, data);
    this.currentSess = new this.wg.DissectSession(filename);
    const ret = this.currentSess.load();
    if (ret.code !== 0) throw new Error("Wiregasm load failed: " + ret.code);
    return this.getFrames(filter);
  }

  async getFrames(filter: string = ""): Promise<any[]> {
    if (!this.currentSess) return [];
    const framesResp = this.currentSess.getFrames(filter, 0, 0); 
    const framesSummary = this.vectorToArray(framesResp.frames);
    const matchedCount = framesResp.matched || 0;
    const packets: any[] = [];
    const processFrame = (num: number, summaryObj: any) => {
        const detail = this.currentSess.getFrame(num);
        if (detail) {
            const pcapPkt = this.currentPackets[num - 1];
            packets.push(this.convertWiregasmToInternal(detail, summaryObj, pcapPkt ? pcapPkt.data : null));
        }
    };
    if (framesSummary.length > 0) {
        for (const f of framesSummary) {
            const rawNum = f.number !== undefined ? f.number : (f.n !== undefined ? f.n : f.num);
            const frameNum = parseInt(rawNum, 10);
            if (!isNaN(frameNum)) processFrame(frameNum, f);
        }
    } else if (matchedCount > 0 && !filter) {
        for (let i = 1; i <= matchedCount; i++) processFrame(i, { number: i });
    }
    return packets;
  }

  private vectorToArray(vec: any): any[] {
      if (!vec) return [];
      if (Array.isArray(vec)) return vec;
      if (typeof vec.size === 'function' && typeof vec.get === 'function') {
          const arr = [];
          const size = vec.size();
          for (let i = 0; i < size; i++) arr.push(vec.get(i));
          return arr;
      }
      return [];
  }

  private addValueToLayer(layer: any, key: string, value: any) {
      if (layer[key] === undefined) {
          layer[key] = value;
      } else {
          // If the existing value is NOT an array of arrays (it's a single tuple or label), 
          // we need to convert it to an array of values.
          // For labels, it's a string. For raw fields, it's a tuple [string, number, ...].
          // We check if the first element is a string to distinguish a single tuple from an array of tuples.
          if (!Array.isArray(layer[key]) || (layer[key].length > 0 && typeof layer[key][0] === 'string')) {
              layer[key] = [layer[key]];
          }
          layer[key].push(value);
      }
  }

  private flattenTree(node: any, rootLayers: any, currentLayer: any, packetData: Uint8Array | null) {
      if (!node) return;
      const rawFilter = this.getProp(node, 'filter');
      const filter = this.cleanFilter(rawFilter);
      const type = this.getProp(node, 'type');
      const label = this.getProp(node, 'label');
      const start = this.getProp(node, 'start');
      const length = this.getProp(node, 'length');
      let nextLayer = currentLayer;
      if (filter) {
          if (type === 'proto') {
              if (typeof rootLayers[filter] !== 'object' || rootLayers[filter] === null || Array.isArray(rootLayers[filter])) {
                  rootLayers[filter] = {};
              }
              nextLayer = rootLayers[filter];
              if (!nextLayer['_description']) nextLayer['_description'] = label;
          } else {
              this.addValueToLayer(currentLayer, filter, label);
          }
          if (start !== undefined && length !== undefined && packetData) {
              if (start >= 0 && start < packetData.length) {
                  let validLength = length;
                  if (start + validLength > packetData.length) {
                      validLength = packetData.length - start;
                  }
                  
                  const slice = packetData.slice(start, start + validLength);
                  const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join('');
                  const key = filter + '_raw';
                  const rawVal = [hex, start, validLength, 0, 1];
                  if (type === 'proto') this.addValueToLayer(nextLayer, key, rawVal);
                  else this.addValueToLayer(currentLayer, key, rawVal);
              } else {
                  console.warn(`Skipping raw for ${filter}: start=${start} len=${length} pktLen=${packetData.length}`);
              }
          } else if (filter && (start === undefined || length === undefined)) {
              // console.debug(`No raw info for ${filter}`);
          }
      }
      const childrenVec = this.getProp(node, 'tree') || this.getProp(node, 'n');
      if (childrenVec) {
          const children = this.vectorToArray(childrenVec);
          for (const child of children) this.flattenTree(child, rootLayers, nextLayer, packetData);
      }
  }

  private convertWiregasmToInternal(detail: any, summary: any, packetData: Uint8Array | null): any {
    const layers: any = {};
    if (packetData) {
        const hex = Array.from(packetData).map(b => b.toString(16).padStart(2, '0')).join('');
        layers['frame_raw'] = [hex, 0, packetData.length, 0, 1];
        layers['frame'] = { 'frame.len': packetData.length };
        if (summary.t) layers['frame']['frame.time_epoch'] = summary.t;
    }
    const treeNodes = this.vectorToArray(this.getProp(detail, 'tree'));
    for (const node of treeNodes) this.flattenTree(node, layers, layers, packetData);
    return {
        _source: { layers },
        _summary: { ...summary, c: this.vectorToArray(summary.columns) }
    };
  }
}
