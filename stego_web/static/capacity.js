/* Pure helpers for interpreting payload capacity and layout suggestions. */
(() => {
  function fitsAtStart(startUnit, bootstrapSpan, maxStartUnit) {
    return Number.isSafeInteger(startUnit)
      && Number.isSafeInteger(bootstrapSpan)
      && Number.isSafeInteger(maxStartUnit)
      && startUnit >= bootstrapSpan
      && startUnit <= maxStartUnit;
  }

  function startRange(bootstrapSpan, lsbBits, lsbResults) {
    if (!Number.isSafeInteger(bootstrapSpan) || bootstrapSpan < 0
        || !Number.isSafeInteger(lsbBits) || lsbBits < 1 || lsbBits > 8
        || !Array.isArray(lsbResults)) return null;
    const entry = lsbResults.find(result => result && result.lsb_bits === lsbBits);
    if (!entry || !Number.isSafeInteger(entry.max_start_unit)
        || entry.max_start_unit < bootstrapSpan) return null;
    return {min: bootstrapSpan, max: entry.max_start_unit};
  }

  function clampStart(start, range) {
    if (!Number.isSafeInteger(start) || !range
        || !Number.isSafeInteger(range.min) || !Number.isSafeInteger(range.max)
        || range.min < 0 || range.max < range.min) return null;
    return Math.min(range.max, Math.max(range.min, start));
  }

  function findLsbSuggestion(startUnit, bootstrapSpan, lsbResults) {
    if (!Number.isSafeInteger(startUnit)
        || !Number.isSafeInteger(bootstrapSpan)
        || startUnit < bootstrapSpan
        || !Array.isArray(lsbResults)) return null;
    const candidate = lsbResults
      .filter(entry => entry && Number.isSafeInteger(entry.lsb_bits)
        && entry.lsb_bits >= 1 && entry.lsb_bits <= 8
        && Number.isSafeInteger(entry.max_start_unit)
        && entry.max_start_unit >= startUnit)
      .sort((left, right) => left.lsb_bits - right.lsb_bits)[0];
    return candidate ? candidate.lsb_bits : null;
  }

  function evaluateLayout(startUnit, bootstrapSpan, lsbBits, lsbResults) {
    const entries = Array.isArray(lsbResults) ? lsbResults : [];
    const current = entries.find(entry => entry && entry.lsb_bits === lsbBits);
    const latestStartUnit = current && Number.isSafeInteger(current.max_start_unit)
      ? current.max_start_unit : null;
    const fits = fitsAtStart(startUnit, bootstrapSpan, latestStartUnit);
    const suggestedLsb = fits
      ? null : findLsbSuggestion(startUnit, bootstrapSpan, entries);
    const suggestion = suggestedLsb !== null
      ? {type: 'lsb', lsbBits: suggestedLsb}
      : Number.isSafeInteger(latestStartUnit)
        ? {type: 'start', startUnit: latestStartUnit}
        : null;
    return {
      fits,
      latestStartUnit,
      suggestion,
      fitsAnywhere: entries.some(entry => entry
        && Number.isSafeInteger(entry.max_start_unit)),
    };
  }

  window.StegoCapacity = Object.freeze({
    clampStart,
    evaluateLayout,
    findLsbSuggestion,
    fitsAtStart,
    startRange,
  });
})();
