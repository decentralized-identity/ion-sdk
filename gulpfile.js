
const fs = require('fs-extra');
const gulp = require('gulp');
const concat = require('gulp-concat');
const terser = require('gulp-terser');

const destination = 'dist';

const bundle = [
  'dist/raw-sdk.js',
  'lib/wrapper.js'
];

const compile = async function () {
  await fs.ensureDir(destination);
  gulp.src(bundle)
    .pipe(terser())
    .pipe(concat('ion.js'))
    .pipe(gulp.dest(destination));
};

gulp.task('compile', compile);
