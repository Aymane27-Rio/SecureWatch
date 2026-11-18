FROM node:24.22.3-alpine3.24 AS build
WORKDIR /app
ENV NODE_ENV=development
COPY package.json package-lock.json ./
RUN npm ci --include=dev \
    && if [ ! -x node_modules/.bin/vite ]; then \
        echo "Vite was not installed; check npm registry access and dev dependency settings." >&2; \
        exit 1; \
    fi
COPY . .
RUN npm run build

FROM nginx/nginx-unprivileged:1.31.8-alpine3.24
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --chmod=0555 validate-api-key.sh /docker-entrypoint.d/10-validate-api-key.sh
ENV NGINX_ENVSUBST_FILTER=^WEBAPI_API_KEY
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
