const path = require("path");
const fs = require("fs");
const { createHash } = require("crypto");

const baseUrl = "https://cdn-pkg.foxnb.net/app_image/static/aleo_params/";
const ignoreFiles = [".DS_Store"];
const dirPath = path.join(__dirname, "../rust/src/aleo_params_2");

const files = fs.readdirSync(dirPath);

let res = [];

for (let file of files) {
  if (ignoreFiles.includes(file)) continue;
  const filePath = path.join(dirPath, file);
  const stats = fs.statSync(filePath);
  const fileSizeInBytes = stats.size;
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = createHash("sha256");
  hashSum.update(fileBuffer);
  const hex = hashSum.digest("hex");

  res.push({
    fileName: file,
    url: `${baseUrl}${file}`,
    sha256: hex,
    size: fileSizeInBytes,
  });
}

const totalSize = res.reduce((acc, cur) => acc + cur.size, 0);

for (let item of res) {
  item.ratio = Math.floor((item.size / totalSize) * 100);
  delete item.size;
}

const totalRatio = res.reduce((acc, cur) => acc + cur.ratio, 0);

const diff = 100 - totalRatio;

res[res.length - 1].ratio += diff;

console.log(
  res,
  res.reduce((acc, cur) => acc + cur.ratio, 0)
);
