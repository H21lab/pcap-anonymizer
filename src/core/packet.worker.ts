
/* eslint-disable no-restricted-globals */
import { processPackets } from './packetProcessor';

self.onmessage = (e: MessageEvent) => {
  const { packets, config } = e.data;
  try {
    const blob = processPackets(packets, config);
    self.postMessage({ type: 'success', blob });
  } catch (error: any) {
    self.postMessage({ type: 'error', error: error.message });
  }
};
