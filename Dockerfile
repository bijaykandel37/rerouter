# --- build the web UI -------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build   # outputs to ../backend/rerouter/static

# --- runtime ----------------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app
COPY backend/ ./backend/
COPY --from=ui /src/backend/rerouter/static ./backend/rerouter/static
RUN pip install --no-cache-dir ./backend && useradd -r -u 10001 rerouter \
    && mkdir -p /data && chown rerouter /data
ENV REROUTER_DATA_DIR=/data
VOLUME /data
EXPOSE 8080/tcp 2055/udp
USER rerouter
CMD ["rerouter"]
