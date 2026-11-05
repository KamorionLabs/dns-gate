// Resolves extensionless relative imports of the sources ("./glob") to their
// .ts file, as Vite does, so modules can be tested without a bundler.
import { registerHooks } from 'node:module';

registerHooks({
  resolve(specifier, context, next) {
    try {
      return next(specifier, context);
    } catch (e) {
      if (/^\.\.?\//.test(specifier) && !/\.[cm]?[jt]s$/.test(specifier)) return next(specifier + '.ts', context);
      throw e;
    }
  },
});
