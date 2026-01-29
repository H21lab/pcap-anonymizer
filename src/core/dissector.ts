
import { PcapParser } from '../utils/pcapParser';
import { SimpleDissector } from './simpleDissector';
import { WiregasmDissector } from './wiregasmDissector';

export class WasmDissector {
  private wiregasm = new WiregasmDissector();
  private isFileLoaded: boolean = false;

  async dissect(file: File, filter: string = ""): Promise<any[]> {
    this.isFileLoaded = false;
    
    // Try Wiregasm first
    try {
        const packets = await this.wiregasm.dissect(file, filter);
        this.isFileLoaded = true;
        return packets;
    } catch (e) {
        console.warn("Wiregasm failed, falling back to simple JS dissector:", e);
    }

    const arrayBuffer = await file.arrayBuffer();
    // Fallback to Simple JS Dissector
    try {
        const parser = new PcapParser(arrayBuffer);
        const pcapPackets = parser.parse();
        const dissector = new SimpleDissector();
        return dissector.dissect(pcapPackets);
    } catch (e: any) {
        throw new Error("Failed to parse PCAP (Simple): " + e.message);
    }
  }

  async reDissect(filter: string): Promise<any[]> {
      if (!this.isFileLoaded) return [];
      return this.wiregasm.getFrames(filter);
  }
}
