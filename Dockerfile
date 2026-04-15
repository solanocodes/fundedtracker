FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY site/ ./site/

EXPOSE 8080

CMD ["node", "server.js"]
