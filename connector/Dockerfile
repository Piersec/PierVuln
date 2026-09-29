FROM node:24-alpine
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
COPY pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json next.config.ts next-env.d.ts ./
COPY connector ./connector
COPY src ./src
ENV NODE_ENV=production
CMD ["pnpm", "connector:run"]
