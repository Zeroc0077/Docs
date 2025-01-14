import sys
import httpx
import re
import os

md_path = sys.argv[1]
save_dir = sys.argv[2]
# check if the save_dir exists
if not os.path.exists(save_dir):
    print(f"{save_dir} does not exist")
    os.mkdir(save_dir)

# relative path of the md to the save_dir
relative_path = os.path.relpath(save_dir, os.path.dirname(md_path))
print(f"relative path: {relative_path}")

md_image_url_pattern = re.compile(r"!\[.*?\]\((.*?)\)")
md_content = open(md_path, "r").read()
image_urls = md_image_url_pattern.findall(md_content)

index = 0
for image_url in image_urls:
    print(f"downloading image: {image_url}")
    response = httpx.get(image_url)
    image_name = f"img_{index}.png"
    with open(f"{save_dir}/{image_name}", "wb") as f:
        f.write(response.content)
    # replace the image url in the markdown content
    md_content = md_content.replace(image_url, f"{relative_path}/{image_name}")
    index += 1

# write the updated content back to the md file
with open(md_path, "w") as f:
    f.write(md_content)
