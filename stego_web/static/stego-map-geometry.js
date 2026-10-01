export const CHANNELS_PER_PIXEL = 3;
export const DEFAULT_BOOTSTRAP_UNITS = 2048;

function requireInteger(value, label, minimum = 0) {
  if (!Number.isInteger(value) || value < minimum) {
    throw new RangeError(`${label} must be an integer of at least ${minimum}`);
  }
  return value;
}

function requireDimensions(width, height) {
  requireInteger(width, 'width', 1);
  requireInteger(height, 'height', 1);
}

export function pixelToStartUnit(x, y, width, height) {
  requireDimensions(width, height);
  requireInteger(x, 'x');
  requireInteger(y, 'y');
  if (x >= width || y >= height) throw new RangeError('pixel is outside the image');
  return (y * width + x) * CHANNELS_PER_PIXEL;
}

export function startUnitToPixel(startUnit, width, height) {
  requireDimensions(width, height);
  requireInteger(startUnit, 'startUnit');
  const totalUnits = width * height * CHANNELS_PER_PIXEL;
  if (startUnit >= totalUnits) throw new RangeError('startUnit is outside the image');
  const pixelIndex = Math.floor(startUnit / CHANNELS_PER_PIXEL);
  return {
    x: pixelIndex % width,
    y: Math.floor(pixelIndex / width),
    pixelIndex,
    channel: startUnit % CHANNELS_PER_PIXEL,
  };
}

export function uvToPixel(u, v, width, height) {
  requireDimensions(width, height);
  if (!Number.isFinite(u) || !Number.isFinite(v)) throw new TypeError('u and v must be finite');
  const boundedU = Math.min(1, Math.max(0, u));
  const boundedV = Math.min(1, Math.max(0, v));
  return {
    x: Math.min(width - 1, Math.floor(boundedU * width)),
    y: Math.min(height - 1, Math.floor((1 - boundedV) * height)),
  };
}

export function carrierRangeToPixelRectangles(startUnit, footprint, width, height) {
  requireDimensions(width, height);
  requireInteger(startUnit, 'startUnit');
  requireInteger(footprint, 'footprint');
  const totalUnits = width * height * CHANNELS_PER_PIXEL;
  if (startUnit > totalUnits || startUnit + footprint > totalUnits) {
    throw new RangeError('carrier range is outside the image');
  }
  if (footprint === 0) return [];

  const startPixel = Math.floor(startUnit / CHANNELS_PER_PIXEL);
  const endPixelExclusive = Math.ceil((startUnit + footprint) / CHANNELS_PER_PIXEL);
  const firstRow = Math.floor(startPixel / width);
  const lastPixel = endPixelExclusive - 1;
  const lastRow = Math.floor(lastPixel / width);
  const firstX = startPixel % width;
  const lastX = lastPixel % width;

  if (firstRow === lastRow) {
    return [{x: firstX, y: firstRow, width: lastX - firstX + 1, height: 1}];
  }

  const rectangles = [{x: firstX, y: firstRow, width: width - firstX, height: 1}];
  const middleHeight = lastRow - firstRow - 1;
  if (middleHeight > 0) {
    rectangles.push({x: 0, y: firstRow + 1, width, height: middleHeight});
  }
  rectangles.push({x: 0, y: lastRow, width: lastX + 1, height: 1});
  return rectangles;
}

export function firstSelectablePixelUnit(bootstrapUnits, width, height) {
  requireDimensions(width, height);
  requireInteger(bootstrapUnits, 'bootstrapUnits');
  const unit = Math.ceil(bootstrapUnits / CHANNELS_PER_PIXEL) * CHANNELS_PER_PIXEL;
  if (unit >= width * height * CHANNELS_PER_PIXEL) return null;
  return unit;
}
