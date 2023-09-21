import React, { useState } from "react";
import ReactQuill from "react-quill";
import "react-quill/dist/quill.snow.css";
import axios from "axios";
import { useLocation, useNavigate } from "react-router-dom";
import moment from "moment";

const Write = () => {
  const state = useLocation().state;
  const [title, setTitle] = useState(state?.title || "");
  const [value, setValue] = useState(state?.desc || "");
  const [file, setFile] = useState(null);
  const [cat, setCat] = useState(state?.cat || "");
  const [err, setError] = useState(null);

  const navigate = useNavigate();

  const upload = async () => {
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await axios.post("/upload", formData);
      return res.data;
    } catch (err) {
      setError(err.response.data);
    }
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleCategoryChange = (e) => {
    setCat(e.target.value);
  };

  const handleClick = async (e) => {
    e.preventDefault();

    let imgUrl = "";

    if (file) {
      imgUrl = await upload();
    }

    // Check if required fields are empty or contain only spaces
    const trimmedTitle = title.trim();

    if (!trimmedTitle || !value || !cat) {
      setError("Please fill in all required fields.");
      return;
    }

    try {
      if (state) {
        await axios.put(`/posts/${state.id}`, {
          title,
          desc: value,
          cat,
          postImg: imgUrl || state.postImg,
        });
      } else {
        if (!file) {
          setError("Please select an image file.");
          return;
        }
        await axios.post(`/posts`, {
          title,
          desc: value,
          cat,
          postImg: imgUrl,
          date: moment(Date.now()).format("YYYY-MM-DD HH:mm:ss"),
        });
      }
      navigate("/");
    } catch (err) {
      setError(err.response.data);
    }
  };

  return (
    <>
      {err && <p className="error">{err}</p>}
      <div className="add">
        <div className="content">
          <input
            type="text"
            placeholder="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
          <div className="editorContainer">
            <ReactQuill
              className="editor"
              theme="snow"
              value={value}
              onChange={setValue}
            />
          </div>
        </div>
        <div className="menu">
          <div className="item">
            <h1>Publish</h1>
            <span>
              <b>Status: </b> Draft
            </span>
            <span>
              <b>Visibility: </b> Public
            </span>
            <input type="file" id="file" name="" onChange={handleFileChange} />
            <div className="buttons">
              <button onClick={handleClick}>Publish</button>
            </div>
          </div>
          <div className="item">
            <h1>Category</h1>
            {["art", "science", "technology", "cinema", "design", "food"].map(
              (category) => (
                <div className="cat" key={category}>
                  <input
                    type="radio"
                    checked={cat === category}
                    name="cat"
                    value={category}
                    id={category}
                    onChange={handleCategoryChange}
                  />
                  <label htmlFor={category}>{category}</label>
                </div>
              )
            )}
          </div>
        </div>
      </div>
    </>
  );
};

export default Write;
