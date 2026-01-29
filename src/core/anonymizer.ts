
import { shake256 } from 'js-sha3';

export class AnonymizedField {
  field: string;
  type: number; // 0 for masking (0xff), 1 for shake_256
  start: number | null = null;
  end: number | null = null;

  constructor(fieldArg: string, type: number) {
    this.field = fieldArg;
    this.type = type;

    // Parse field[start:end]
    const match = fieldArg.match(/(\S+)\[(-?\d+)?:(-?\d+)?\]/);
    if (match) {
      this.field = match[1];
      if (match[2] !== undefined) {
        this.start = parseInt(match[2], 10);
      }
      if (match[3] !== undefined) {
        this.end = parseInt(match[3], 10);
      }
    }
  }

  anonymizeFieldShake256(field: string, type: number, salt: string): string {
    // Input 'field' is a hex string
    const inputString = field + ':' + salt;
    // shake256 needs bits.
    // Python: shake.hexdigest(length) returns 'length' bytes of hex.
    
    let retString = '';

    // String types in Wireshark often correspond to these IDs (from scapy/wireshark mapping?)
    // In the python script: 26, 27, 28 are treated as strings.
    if ([26, 27, 28].includes(type)) {
      const length = Math.ceil(field.length / 4);
      // Generate hash of 'length' bytes.
      const shakeHash = shake256(inputString, length * 8); // returns hex string
      
      // Convert the hex string characters to their ASCII hex values
      // e.g. hash="a1" -> 'a','1' -> 0x61, 0x31 -> "6131"
      for (let i = 0; i < shakeHash.length; i++) {
        retString += shakeHash.charCodeAt(i).toString(16).padStart(2, '0');
      }
    } else {
      const length = Math.ceil(field.length / 2);
      retString = shake256(inputString, length * 8);
    }

    // Correct string length
    if (retString.length < field.length) {
      retString = retString.padEnd(field.length, '0'); // padding char? Python uses ljust which spaces by default? 
      // Python: ret_string.ljust(len(field)). ljust uses space ' ' by default if not specified? 
      // Wait, ljust on a string uses spaces.
      // But ret_string in python 'else' block is hex digits. ljust with space would add ' '.
      // ' ' in hex is 0x20. But here we are returning a hex string.
      // If we add ' ' to a hex string, it becomes invalid hex if we expect pure hex.
      // However, rewrite_frame just does string concat.
      // If the field type expects hex, adding spaces is weird.
      // Let's assume '0' padding for hex safety, or maybe the python script implies the string logic handles it.
      // Actually, looking at python:
      // ret_string = ret_string.ljust(len(field))
      // If ret_string is "a1b2", ljust(6) -> "a1b2  ".
      // This "  " might be interpreted later.
      // But for hex reconstruction, having spaces in 'h' passed to 'rewrite_frame' 
      // -> 'frame_raw_new = ... + h + ...'.
      // Then 'scapy.Packet(bytearray.fromhex(output))'. 
      // fromhex fails with spaces? Actually it might ignore whitespace or fail.
      // scapy/python `bytearray.fromhex` *ignores* whitespace.
      // So ' ' is fine.
      // But for `js-sha3` output, I'll stick to '0' or just cycle? 
      // Let's use '0' to be safe and clean.
       retString = retString.padEnd(field.length, '0');
    }
    if (retString.length > field.length) {
      retString = retString.substring(0, field.length);
    }

    return retString;
  }

  anonymize(hFull: string, t: number, salt: string): [string, string] {
    let s = 0;
    let e = hFull.length;

    if (this.start !== null) {
      s = this.start;
      if (s < 0) {
        s = hFull.length + s;
      }
    }
    
    // Handle negative indices
    if (this.end !== null) {
      e = this.end;
      if (e < 0) {
        e = hFull.length + e;
      }
    }

    // Ensure indices are within bounds
    s = Math.max(0, Math.min(s, hFull.length));
    e = Math.max(s, Math.min(e, hFull.length));
    
    let hPart = hFull.substring(s, e);
    
    if (this.type === 0) {
      // Masking with 0xff
      hPart = 'f'.repeat(hPart.length);
    } else if (this.type === 1) {
      hPart = this.anonymizeFieldShake256(hPart, t, salt);
    }

    // Construct mask
    // '0' * len(_h[0:s]) + 'f' * len(hPart) + '0' * len(_h[e:])
    // 0 means modifiable (original), f means not modifiable (anonymized/masked) 
    // Wait, in python `rewrite_frame`:
    // mask 'ff' -> preserve original.
    // mask '00' -> overwrite.
    // 
    // Here:
    // `h_mask = '0' * len(_h[0:s]) + 'f' * len(h) + '0' * len(_h[e:])`
    // This creates a mask where the *anonymized part* is 'f's.
    //
    // Then in `py_generator` loop:
    // `h_mask = 'f' * len(h)` (initial default)
    // `[h, h_mask] = anonymize...`
    //
    // Then: `frame_mmask = rewrite_frame(frame_mmask, h_mask, ...)`
    //
    // Wait, let's look at `multiply_strings` usage in `rewrite_frame`:
    // `multiply_strings(frame_raw, frame_raw_new, frame_mmask)`
    // If mask is 'ff', `ret_string` keeps `original`.
    // If mask is '00', `ret_string` takes `new`.
    //
    // If we want to *apply* the anonymized value, we want the mask to allow it.
    // So the anonymized part should correspond to '00'?
    //
    // Python script `anonymize_field`:
    // Returns `h_mask`.
    // `h_mask = '0' ... + 'f' ... + '0' ...`
    // So the part we *changed* (hPart) gets 'f's?
    //
    // Then `rewrite_frame(frame_mmask, h_mask, ...)`
    // This updates the global `frame_mmask`.
    //
    // If `frame_mmask` has 'ff' at a position, `rewrite_frame` (applied later to the frame itself) 
    // will preserve the original `frame_raw` at that position, ignoring the `h` we passed.
    //
    // So if `anonymize_field` returns 'f's for the anonymized part,
    // and `frame_mmask` accumulates these 'f's.
    // Then `rewrite_frame` for the actual data will SEE 'ff' and PRESERVE original.
    // This implies the anonymization would be IGNORED?
    //
    // Let's re-read `multiply_strings`:
    // `if mask[i:i + 2] == 'ff': ret_string = ... + original_string[...]`
    //
    // If I want to *change* the value to the anonymized one, I should NOT have 'ff' in the mask.
    //
    // Maybe `anonymize_field` is returning the mask for *other* purposes?
    // Or I misunderstood the mask logic.
    //
    // Python:
    // `h_mask = '0' * len(_h[0:s]) + 'f' * len(h) + '0' * len(_h[e:])`
    // So the part being anonymized gets 'f'.
    //
    // The loop:
    // `s1 = frame_raw`
    // `frame_raw = rewrite_frame(frame_raw, _h, _p, _l, _b, _t, frame_mmask)`
    //
    // `frame_mmask` is initialized to "0"*len.
    //
    // If `frame_mmask` is all '0', `rewrite_frame` (via `multiply_strings`) sees '00' (not 'ff').
    // So it takes `new_string` (which contains `_h`).
    // So the change IS applied.
    //
    // AFTER applying the change:
    // `frame_mmask = rewrite_frame(frame_mmask, _h_mask, ...)`
    //
    // So we update the mask *after* usage.
    // If we anonymized a field (got 'f's in mask), we write 'f's into `frame_mmask` at that position.
    //
    // LATER, if another field (maybe a lower layer or overlapping field) tries to write to that same position:
    // It calls `rewrite_frame(..., frame_mmask)`.
    // `frame_mmask` now has 'ff' at that spot.
    // So `rewrite_frame` sees 'ff' and *preserves* the `original` (which is the current `frame_raw`, i.e., the *already anonymized* value? No).
    //
    // `multiply_strings(original_string, new_string, mask)`
    // `original_string` is the `frame_raw` passed in.
    //
    // If I am at step 2.
    // `frame_raw` has step 1's changes.
    // I call `rewrite_frame(frame_raw, ...)`
    // inside: `frame_raw_new` has step 2's changes.
    // `multiply_strings(frame_raw, frame_raw_new, mask)`
    // If mask is 'ff', we keep `frame_raw` (current state).
    // If mask is '00', we take `frame_raw_new` (new state).
    //
    // So:
    // 1. Anonymize IP (upper layer). Mark that area as 'ff' in mask.
    // 2. Later, we process Ethernet (lower layer, containing IP).
    //    Ethernet tries to rewrite the whole frame (including IP payload).
    //    But mask has 'ff' at IP position.
    //    So we keep the IP part from `frame_raw` (which is anonymized), ignoring the "raw" bytes from Ethernet field (which are original).
    //
    // This logic ensures that specific anonymized fields are not overwritten by larger containing fields.
    //
    // Conclusion:
    // The mask 'f' means "PROTECTED/ALREADY MODIFIED".
    //
    // Implementation seems correct.
    
    const hMask = '0'.repeat(s) + 'f'.repeat(hPart.length) + '0'.repeat(hFull.length - e);
    const hNew = hFull.substring(0, s) + hPart + hFull.substring(e);

    return [hNew, hMask];
  }
}
