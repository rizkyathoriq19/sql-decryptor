import { formatDialect, transactsql } from 'sql-formatter';

self.onmessage = ({ data }: MessageEvent<string>) => {
  try {
    self.postMessage({ formatted: formatDialect(data, { dialect: transactsql, tabWidth: 2, keywordCase: 'preserve' }) });
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
