const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function isHighSurrogate(codeUnit) {
  return codeUnit >= 0xd800 && codeUnit <= 0xdbff;
}

function isLowSurrogate(codeUnit) {
  return codeUnit >= 0xdc00 && codeUnit <= 0xdfff;
}

export function assertNoLoneSurrogates(value, field = 'string') {
  if (typeof value !== 'string') {
    throw new Error(`${field} must be a string`);
  }
  for (let i = 0; i < value.length; i += 1) {
    const codeUnit = value.charCodeAt(i);
    if (isHighSurrogate(codeUnit)) {
      const next = value.charCodeAt(i + 1);
      if (!isLowSurrogate(next)) {
        throw new Error(`Invalid ${field}: lone surrogate`);
      }
      i += 1;
      continue;
    }
    if (isLowSurrogate(codeUnit)) {
      throw new Error(`Invalid ${field}: lone surrogate`);
    }
  }
  return value;
}

export function decodeUtf8JsonBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('JSON bytes must be Uint8Array');
  }
  try {
    return utf8Decoder.decode(bytes);
  } catch (error) {
    throw new Error(`Invalid UTF-8 JSON: ${error?.message || error}`);
  }
}

const NUMBER_TOKEN_RE = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;

class StrictJsonParser {
  constructor(text) {
    this.text = text;
    this.pos = 0;
  }

  fail(message) {
    throw new Error(`${message} at character ${this.pos}`);
  }

  peek() {
    return this.text.charCodeAt(this.pos);
  }

  skipWhitespace() {
    while (this.pos < this.text.length) {
      const codeUnit = this.text.charCodeAt(this.pos);
      if (codeUnit === 0x20 || codeUnit === 0x09 || codeUnit === 0x0a || codeUnit === 0x0d) {
        this.pos += 1;
        continue;
      }
      break;
    }
  }

  parse() {
    this.skipWhitespace();
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.pos !== this.text.length) {
      this.fail('Unexpected trailing data');
    }
    return value;
  }

  parseValue() {
    this.skipWhitespace();
    if (this.pos >= this.text.length) {
      this.fail('Unexpected end of JSON input');
    }
    const codeUnit = this.peek();
    if (codeUnit === 0x7b) return this.parseObject();
    if (codeUnit === 0x5b) return this.parseArray();
    if (codeUnit === 0x22) return this.parseString();
    if (codeUnit === 0x74) return this.parseLiteral('true', true);
    if (codeUnit === 0x66) return this.parseLiteral('false', false);
    if (codeUnit === 0x6e) return this.parseLiteral('null', null);
    if (codeUnit === 0x2d || (codeUnit >= 0x30 && codeUnit <= 0x39)) return this.parseNumber();
    this.fail('Unexpected token');
  }

  parseLiteral(token, value) {
    if (this.text.slice(this.pos, this.pos + token.length) !== token) {
      this.fail(`Unexpected token, expected ${token}`);
    }
    this.pos += token.length;
    return value;
  }

  parseNumber() {
    const match = NUMBER_TOKEN_RE.exec(this.text.slice(this.pos));
    if (!match || match.index !== 0) {
      this.fail('Invalid number');
    }
    const token = match[0];
    this.pos += token.length;
    return JSON.parse(token);
  }

  parseHex4() {
    if (this.pos + 4 > this.text.length) {
      this.fail('Incomplete Unicode escape');
    }
    const token = this.text.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(token)) {
      this.fail('Invalid Unicode escape');
    }
    this.pos += 4;
    return Number.parseInt(token, 16);
  }

  parseUnicodeEscape() {
    const codeUnit = this.parseHex4();
    if (isHighSurrogate(codeUnit)) {
      if (this.text.charCodeAt(this.pos) !== 0x5c || this.text.charCodeAt(this.pos + 1) !== 0x75) {
        this.fail('Lone high surrogate in JSON string');
      }
      this.pos += 2;
      const low = this.parseHex4();
      if (!isLowSurrogate(low)) {
        this.fail('Lone high surrogate in JSON string');
      }
      return String.fromCharCode(codeUnit, low);
    }
    if (isLowSurrogate(codeUnit)) {
      this.fail('Lone low surrogate in JSON string');
    }
    return String.fromCharCode(codeUnit);
  }

  parseString() {
    if (this.peek() !== 0x22) {
      this.fail('Expected string');
    }
    this.pos += 1;
    let out = '';
    while (this.pos < this.text.length) {
      const codeUnit = this.text.charCodeAt(this.pos);
      this.pos += 1;
      if (codeUnit === 0x22) {
        return out;
      }
      if (codeUnit === 0x5c) {
        if (this.pos >= this.text.length) {
          this.fail('Unterminated escape sequence');
        }
        const escaped = this.text.charCodeAt(this.pos);
        this.pos += 1;
        switch (escaped) {
          case 0x22: out += '"'; break;
          case 0x5c: out += '\\'; break;
          case 0x2f: out += '/'; break;
          case 0x62: out += '\b'; break;
          case 0x66: out += '\f'; break;
          case 0x6e: out += '\n'; break;
          case 0x72: out += '\r'; break;
          case 0x74: out += '\t'; break;
          case 0x75: out += this.parseUnicodeEscape(); break;
          default:
            this.fail('Invalid escape sequence');
        }
        continue;
      }
      if (codeUnit < 0x20) {
        this.fail('Unescaped control character in JSON string');
      }
      if (isHighSurrogate(codeUnit)) {
        const low = this.text.charCodeAt(this.pos);
        if (!isLowSurrogate(low)) {
          this.fail('Lone high surrogate in JSON string');
        }
        out += String.fromCharCode(codeUnit, low);
        this.pos += 1;
        continue;
      }
      if (isLowSurrogate(codeUnit)) {
        this.fail('Lone low surrogate in JSON string');
      }
      out += String.fromCharCode(codeUnit);
    }
    this.fail('Unterminated string');
  }

  parseArray() {
    if (this.peek() !== 0x5b) {
      this.fail('Expected array');
    }
    this.pos += 1;
    this.skipWhitespace();
    const out = [];
    if (this.peek() === 0x5d) {
      this.pos += 1;
      return out;
    }
    while (true) {
      out.push(this.parseValue());
      this.skipWhitespace();
      const codeUnit = this.peek();
      if (codeUnit === 0x2c) {
        this.pos += 1;
        this.skipWhitespace();
        continue;
      }
      if (codeUnit === 0x5d) {
        this.pos += 1;
        return out;
      }
      this.fail('Expected "," or "]" in array');
    }
  }

  parseObject() {
    if (this.peek() !== 0x7b) {
      this.fail('Expected object');
    }
    this.pos += 1;
    this.skipWhitespace();
    const out = {};
    const seen = new Set();
    if (this.peek() === 0x7d) {
      this.pos += 1;
      return out;
    }
    while (true) {
      if (this.peek() !== 0x22) {
        this.fail('Expected string key');
      }
      const key = this.parseString();
      if (seen.has(key)) {
        this.fail(`Duplicate object key "${key}"`);
      }
      seen.add(key);
      this.skipWhitespace();
      if (this.peek() !== 0x3a) {
        this.fail('Expected ":" after object key');
      }
      this.pos += 1;
      out[key] = this.parseValue();
      this.skipWhitespace();
      const codeUnit = this.peek();
      if (codeUnit === 0x2c) {
        this.pos += 1;
        this.skipWhitespace();
        continue;
      }
      if (codeUnit === 0x7d) {
        this.pos += 1;
        return out;
      }
      this.fail('Expected "," or "}" in object');
    }
  }
}

export function parseJsonTextStrict(text) {
  return new StrictJsonParser(String(text)).parse();
}

export function parseJsonBytesStrict(bytes) {
  return parseJsonTextStrict(decodeUtf8JsonBytes(bytes));
}
