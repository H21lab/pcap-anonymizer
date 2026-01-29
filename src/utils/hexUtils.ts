
/**
 * Replace parts of original_string by new_string, only if mask in the byte is not ff
 * Use for modification mask (00 - further modifiable byte, ff - further not modifiable byte)
 */
export function multiplyStrings(originalString: string, newString: string, mask: string | null): string {
  let retString = newString;
  if (!mask) {
    return retString;
  }

  // Iterate by 2 chars (1 byte)
  const len = Math.min(originalString.length, newString.length, mask.length);
  for (let i = 0; i < len; i += 2) {
    // If mask is 'ff', preserve the original string's byte at this position
    if (mask.substring(i, i + 2).toLowerCase() === 'ff') {
      retString = retString.substring(0, i) + originalString.substring(i, i + 2) + retString.substring(i + 2);
    }
  }

  return retString;
}

/**
 * Rewrite frame
 * @param frameRaw - Original hex string of the frame
 * @param h - Hex string to insert
 * @param p - Position (index in hex string, so nibble index)
 * @param l - Length (length in hex chars, so nibble length)
 * @param b - Bitmask (if 0, simple replacement)
 * @param t - Type (unused in simple replacement)
 * @param frameMmask - Modification mask
 */
export function rewriteFrame(
  frameRaw: string,
  h: string,
  p: number,
  l: number,
  b: number,
  t: number,
  frameMmask: string | null = null
): string {
  if (p < 0 || l <= 0 || !h) {
    return frameRaw;
  }

  // No bitmask
  if (b === 0) {
    let currentL = l;
    if (h.length !== currentL) {
      currentL = h.length;
    }

    // Replace the substring at position p
    const frameRawNew = frameRaw.substring(0, p) + h + frameRaw.substring(p + currentL);
    
    const result = multiplyStrings(frameRaw, frameRawNew, frameMmask);
    
    // console.log(`rewriteFrame pos=${p} len=${l} result_match=${result === frameRaw}`);
    return result;
  } else {
    // Bitmask logic is disabled in original implementation ("not reliable")
    return frameRaw;
  }
}
