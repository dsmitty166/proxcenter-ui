// FORK: test config for the fork's own tests plus upstream's tests of every
// file the fork hooks into. No Postgres global setup: all of these mock
// Prisma, so they run anywhere (`npm run test:fork` is not defined on purpose,
// to keep package.json identical to upstream: use `npx vitest run -c vitest.fork.config.mts`).
//
// The full upstream suite (with Postgres) runs unchanged in upstream's own
// workflows (docker-publish.yml "test" job) on every pull request.
import { defineConfig } from 'vitest/config'
import path from 'path'

import { UPSTREAM_TESTS_OF_HOOKED_FILES } from './src/fork/testing/upstreamTests'

const alias = {
  '@': path.resolve(import.meta.dirname, 'src'),
  '@components': path.resolve(import.meta.dirname, 'src/components'),
  '@configs': path.resolve(import.meta.dirname, 'src/configs'),
  '@assets': path.resolve(import.meta.dirname, 'src/assets'),
  '@core': path.resolve(import.meta.dirname, 'src/@core'),
  '@menu': path.resolve(import.meta.dirname, 'src/@menu'),
  '@layouts': path.resolve(import.meta.dirname, 'src/@layouts'),
  '@views': path.resolve(import.meta.dirname, 'src/views'),
}

export default defineConfig({
  resolve: { alias },
  test: {
    name: 'fork',
    environment: 'node',
    include: ['src/fork/**/*.test.ts', ...UPSTREAM_TESTS_OF_HOOKED_FILES],
  },
})
