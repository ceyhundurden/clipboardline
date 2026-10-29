'use strict';
const dns = require('node:dns').promises;
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
function publicAddress(address) {
  if (address.startsWith('::ffff:')) return publicAddress(address.slice(7));
  if (net.isIP(address) === 4) {
    const p = address.split('.').map(Number); const [a,b,c] = p;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  if (net.isIP(address) === 6) {
    const halves=address.toLowerCase().split('::');let left=halves[0]?halves[0].split(':'):[],right=halves[1]?halves[1].split(':'):[];
    const expand=parts=>parts.flatMap(part=>part.includes('.')?(()=>{const bytes=part.split('.').map(Number);return[((bytes[0]<<8)|bytes[1]).toString(16),((bytes[2]<<8)|bytes[3]).toString(16)];})():[part]);
    left=expand(left);right=expand(right);const words=[...left,...Array(8-left.length-right.length).fill('0'),...right].map(value=>parseInt(value,16));
    return (words[0]&0xe000)===0x2000 && !(words[0]===0x2001&&((words[1]&0xfe00)===0||words[1]===0x0db8)) && words[0]!==0x2002 && !(words[0]===0x3fff&&(words[1]&0xf000)===0);
  }
  return false;
}
async function publicURL(input, resolver = dns.lookup) {
  const url = new URL(input); const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port && !['80', '443'].includes(url.port) ||
      /(^localhost$|\.(local|internal|home|localhost|test|invalid)$)/.test(host)) throw new Error('Only public HTTP(S) destinations are allowed');
  const addresses = net.isIP(host) ? [{address: host, family: net.isIP(host)}] : await resolver(host, {all: true, verbatim: true});
  if (!addresses.length || addresses.some(value => !publicAddress(value.address))) throw new Error('Private network destinations are blocked');
  return {url, address: addresses[0]};
}
async function boundedFetch(input, {maximum = 512 * 1024, redirects = 3, resolver, timeout = 8000, guard} = {}) {
  if(guard)guard(new URL(input));
  const {url, address} = await publicURL(input, resolver);
  return new Promise((resolve, reject) => {
    const request = (url.protocol === 'https:' ? https : http).get(url, {
      headers: {'User-Agent': 'ClipBoardLine/1.7.0', Accept: '*/*'},
      lookup: (_hostname, options, callback) => options.all ? callback(null, [address]) : callback(null, address.address, address.family),
      timeout
    }, response => {
      if ([301,302,303,307,308].includes(response.statusCode)) {
        response.resume(); if (!redirects || !response.headers.location) { reject(new Error('Too many redirects')); return; }
        boundedFetch(new URL(response.headers.location, url).href, {maximum, redirects: redirects - 1, resolver, timeout,guard}).then(resolve, reject); return;
      }
      if (response.statusCode !== 200 || Number(response.headers['content-length'] || 0) > maximum) { response.destroy(); reject(new Error('Remote response is unavailable or too large')); return; }
      const blocks = []; let length = 0;
      response.on('data', block => { length += block.length; if (length > maximum) { response.destroy(new Error('Response exceeds size limit')); } else blocks.push(block); });
      response.on('error', reject); response.on('end', () => resolve({bytes: Buffer.concat(blocks), url: url.href, type: String(response.headers['content-type'] || '')}));
    });
    request.on('timeout', () => request.destroy(new Error('Network request timed out'))); request.on('error', reject);
  });
}
function metadataGuard(url){
  if(url.protocol!=='https:')throw new Error('Automatic link metadata requires HTTPS.');
  const sensitive=new Set(['token','accesstoken','refreshtoken','idtoken','apikey','auth','authorization','authentication','authtoken','code','signature','sig','session','sessionid','state','password','secret','clientsecret','credential','credentials','accesskeyid','key','keypairid','policy','verifier','jwt','bearer']);
  for(const key of url.searchParams.keys()){const normalized=key.toLowerCase().replace(/[^a-z0-9]/g,'');if(/^(xamz|xgoog|oauth)/.test(normalized)||sensitive.has(normalized))throw new Error('Sensitive link parameters are not fetched automatically.');}
}
function metadataFetch(input,options={}){return boundedFetch(input,{...options,guard:metadataGuard});}
const entities = value => value.replace(/&(?:amp|quot|lt|gt|apos|#39|#34);/g, match => ({'&amp;':'&','&quot;':'"','&lt;':'<','&gt;':'>','&apos;':"'",'&#39;':"'",'&#34;':'"'}[match]));
// Scans a start tag's attributes, honoring quoted values, until its closing '>'.
// An unquoted '<' or 4096 characters without '>' ends the attempt, so a page of
// unclosed tags costs linear work instead of a backtracking regex scan.
function tagAttributes(html, start) {
  let quote = '';
  for (let index = start, end = Math.min(html.length, start + 4096); index < end; index++) {
    const ch = html[index];
    if (quote) { if (ch === quote) quote = ''; }
    else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '>') return {text: html.slice(start, index), end: index + 1};
    else if (ch === '<') return null;
  }
  return null;
}
// Uses the first title whose closing tag follows within 2000 characters. Start
// tags and the closing-tag cursor both only move forward, so the work stays linear.
function documentTitle(html) {
  const closing = /<\/title\s*>/gi; let close = null;
  for (const match of html.matchAll(/<title\b/gi)) {
    const tag = tagAttributes(html, match.index + match[0].length); if (!tag) continue;
    if (!close || close.index < tag.end) { closing.lastIndex = tag.end; close = closing.exec(html); if (!close) return ''; }
    if (close.index - tag.end <= 2000) return html.slice(tag.end, close.index);
  }
  return '';
}
function meta(html, name) {
  for (const match of html.matchAll(/<meta\b/gi)) {
    const tag = tagAttributes(html, match.index + match[0].length); if (!tag) continue;
    const attributes = {};
    for (const attr of tag.text.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attributes[attr[1].toLowerCase()] = attr[2] ?? attr[3];
    if ([attributes.property, attributes.name].includes(name)) return entities(attributes.content || '').slice(0, 1000);
  }
  return '';
}
async function linkMetadata(input, fetcher = metadataFetch) {
  metadataGuard(new URL(input));
  const url = new URL(input); const youtube = /^(www\.|m\.)?youtube\.com$/.test(url.hostname) || url.hostname === 'youtu.be';
  if (youtube) {
    const response = await fetcher('https://www.youtube.com/oembed?url=' + encodeURIComponent(url.href) + '&format=json', {maximum: 64 * 1024});
    const data = JSON.parse(response.bytes.toString('utf8'));
    return {title: String(data.title || '').slice(0, 500), author: String(data.author_name || '').slice(0, 200), thumbnail: data.thumbnail_url || ''};
  }
  const response = await fetcher(url.href); if (!/text\/html|application\/xhtml/i.test(response.type)) return {title: url.hostname};
  const html = response.bytes.toString('utf8');
  const title = meta(html, 'og:title') || entities((documentTitle(html) || url.hostname).replace(/<[^>]*>/g, '')).trim();
  let thumbnail = meta(html, 'og:image');
  if (thumbnail) try { thumbnail = new URL(thumbnail, response.url).href; } catch { thumbnail = ''; }
  return {title: title.slice(0, 500), thumbnail};
}
module.exports = {publicAddress, publicURL, boundedFetch, metadataGuard,metadataFetch,linkMetadata};
