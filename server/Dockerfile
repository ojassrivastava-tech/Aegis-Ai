FROM node:24-alpine

WORKDIR /app/server

COPY server/package.json .
RUN npm install --omit=dev

COPY server/ .
COPY dashboard/ /app/dashboard/
COPY data/ /app/data/

EXPOSE 4000

ENV ML_SERVICE_URL=http://ml-service:8000

CMD ["node", "server.js"]
