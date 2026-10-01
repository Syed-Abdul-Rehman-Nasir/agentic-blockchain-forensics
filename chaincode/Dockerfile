#
# Chaincode-as-a-Service image for forensiccc (JavaScript).
# Host-side build avoids peer docker build (broken on Docker Engine 29 / Desktop).
#
FROM node:20-bookworm-slim

ARG CC_SERVER_PORT=9999

WORKDIR /usr/src/app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY index.js ./
COPY lib ./lib
COPY docker/docker-entrypoint.sh /usr/src/app/docker-entrypoint.sh
RUN chmod +x /usr/src/app/docker-entrypoint.sh

ENV PORT=${CC_SERVER_PORT}
EXPOSE ${CC_SERVER_PORT}

USER node
ENTRYPOINT ["/usr/src/app/docker-entrypoint.sh"]
