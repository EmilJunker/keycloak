FROM nginx:alpine
COPY default.conf /etc/nginx/conf.d/default.conf
COPY certs/cert.crt /etc/nginx/cert.crt
COPY certs/cert.key /etc/nginx/cert.key