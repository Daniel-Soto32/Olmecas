import React from "react";

export const Esteban = () => {
  fetch("https://jsonplaceholder.typicode.com/posts?_limit=10")
    .then((response) => response.json())
    .then((data) => console.log(data));
  return <div>Esteban</div>;
};
