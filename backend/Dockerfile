FROM composer:2.7 AS builder

WORKDIR /app

COPY composer.json composer.lock ./

RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

COPY . .

RUN composer dump-autoload --optimize

# --- Stage 2: runtime ---
FROM php:8.3-fpm-alpine

WORKDIR /var/www/html

# Extensiones PHP necesarias
RUN docker-php-ext-install pdo pdo_mysql && \
    apk add --no-cache nginx

# Copiar app desde builder
COPY --from=builder /app .

# Permisos Laravel
RUN chown -R www-data:www-data storage bootstrap/cache

EXPOSE 8000

CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]