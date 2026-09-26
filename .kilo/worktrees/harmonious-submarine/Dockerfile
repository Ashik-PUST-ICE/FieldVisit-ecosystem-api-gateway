# ---- vendor stage: build composer deps ----
FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --no-progress --optimize-autoloader

# ---- app stage: php-fpm alpine with extensions ----
FROM php:8.2-fpm-alpine

# system libs + build tools
RUN apk add --no-cache \
    bash git unzip curl libzip-dev icu-dev oniguruma-dev zlib-dev \
    libpng-dev libjpeg-turbo-dev freetype-dev shadow \
    autoconf g++ make

# PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j$(nproc) pdo_mysql opcache bcmath intl zip gd

# Redis ext
RUN pecl install redis && docker-php-ext-enable redis

# Opcache/JIT tuning
RUN { \
  echo 'opcache.enable=1'; \
  echo 'opcache.enable_cli=1'; \
  echo 'opcache.jit=1255'; \
  echo 'opcache.jit_buffer_size=128M'; \
  echo 'opcache.memory_consumption=256'; \
  echo 'opcache.max_accelerated_files=20000'; \
} > /usr/local/etc/php/conf.d/opcache.ini

# app
WORKDIR /var/www/html
COPY . .
COPY --from=vendor /app/vendor ./vendor

# add entrypoint
COPY ../../docker/entrypoints/laravel-entrypoint.sh /usr/local/bin/laravel-entrypoint.sh
RUN chmod +x /usr/local/bin/laravel-entrypoint.sh

# runtime user
RUN addgroup -g 1000 www && adduser -D -G www -u 1000 www \
 && chown -R www:www /var/www/html
USER www

EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s --retries=5 CMD php -v >/dev/null || exit 1
CMD ["laravel-entrypoint.sh"]
