defmodule Regressions.Cve202648591AttributeInjectionTest do
  use ExUnit.Case, async: true

  # CVE-2026-48591: attribute values (href, src, title, IAL classes, ...) were
  # spliced between double quotes without escaping, so a `"` inside a link
  # destination could terminate the attribute and inject arbitrary new ones.

  describe "a quote in a link destination cannot inject attributes" do
    test "href" do
      html = Earmark.as_html!(~S|[x](http://a" onmouseover="alert(1))|)

      assert html =~ ~s|<a href="http://a&quot; onmouseover=&quot;alert(1)">x</a>|
      refute html =~ ~s| onmouseover="|
    end

    test "href with a title-like payload" do
      html = Earmark.as_html!(~S|[x](http://a "ti" onmouseover="alert(1))|)

      assert html =~ ~s|href="http://a &quot;ti&quot; onmouseover=&quot;alert(1)"|
      refute html =~ ~s| onmouseover="|
    end

    test "image src" do
      html = Earmark.as_html!(~S|![x](http://a" onerror="alert(1))|)

      assert html =~ ~s|<img src="http://a&quot; onerror=&quot;alert(1)" alt="x">|
      refute html =~ ~s| onerror="|
    end

    test "IAL class value" do
      html = Earmark.as_html!("# H1\n{: .a\"b}")

      assert html =~ ~s|<h1 class="a&quot;b">|
    end

    test "attribute values passed straight to Earmark.Transform.transform/2" do
      ast = [{"a", [{"href", ~S|http://a" onmouseover="alert(1)|}], ["x"], %{}}]
      html = Earmark.Transform.transform(ast)

      assert html =~ ~s|<a href="http://a&quot; onmouseover=&quot;alert(1)">x</a>|
      refute html =~ ~s| onmouseover="|
    end

    test "escaping does not depend on the escape: option" do
      html = Earmark.as_html!(~S|[x](http://a" onmouseover="alert(1))|, escape: false)

      assert html =~ ~s|<a href="http://a&quot; onmouseover=&quot;alert(1)">x</a>|
      refute html =~ ~s| onmouseover="|
    end
  end

  describe "other characters in attribute values" do
    test "bare ampersands are escaped" do
      html = Earmark.as_html!("[x](http://a?b=1&c=2)")
      assert html =~ ~s|<a href="http://a?b=1&amp;c=2">x</a>|
    end

    test "existing entities are not double escaped" do
      assert Earmark.as_html!("[x](http://a?b=1&amp;c=2)") =~ ~s|href="http://a?b=1&amp;c=2"|
      assert Earmark.as_html!("[x](http://a&#x22;b)") =~ ~s|href="http://a&#x22;b"|
    end

    test "alt text escaped by the parser is not double escaped" do
      assert Earmark.as_html!(~S|![x" y](http://a)|) =~ ~s|alt="x&quot; y"|
    end

    test "angle brackets are escaped" do
      assert Earmark.as_html!("[x](http://a<b>c)") =~ ~s|<a href="http://a&lt;b&gt;c">x</a>|
    end
  end
end

# SPDX-License-Identifier: Apache-2.0
