
FROM node:18-alpine
LABEL authors="ibraheem"
WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
