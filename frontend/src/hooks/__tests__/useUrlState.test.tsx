import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it } from "vitest";
import { useUrlState } from "../useUrlState";

function Filters() {
  const [search, setSearch] = useUrlState<string>("search", "");
  const [page, setPage] = useUrlState<number>("page", 1);
  const location = useLocation();
  return <><output aria-label="address">{location.search}</output><output aria-label="page">{page}</output><button onClick={() => { setSearch("lab.test"); setPage(1); }}>Filter</button><span>{search}</span></>;
}

it("merges a new filter and page reset in one event without losing the filter", async () => {
  render(<MemoryRouter initialEntries={["/targets?page=3&kind=domain"]}><Filters /></MemoryRouter>);
  fireEvent.click(screen.getByRole("button", { name: "Filter" }));
  await waitFor(() => expect(screen.getByLabelText("address")).toHaveTextContent("search=lab.test"));
  expect(screen.getByLabelText("address")).toHaveTextContent("kind=domain");
  expect(screen.getByLabelText("address")).not.toHaveTextContent("page=");
});

it("falls back to the first page for malformed URL page values", () => {
  render(<MemoryRouter initialEntries={["/targets?page=invalid"]}><Filters /></MemoryRouter>);
  expect(screen.getByLabelText("page")).toHaveTextContent("1");
});
