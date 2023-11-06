
from typing import Any
from bs4 import BeautifulSoup
import re
from cleantext import clean
class Preprocessor:
    def __init__(self,helper):
        super().__init__() #this is not used for now. Idea is to create a TextProcessor class and have Preprocessor and Postprocessor inherit from it.
        self.helper=helper

    
    def _process_blockquote_tags(self,text):
        """Processes html content and re-formats blockquote parts
            Args:
                text: html content text
            Returns:
                processed Beautiful soup object
            """
        soup = BeautifulSoup(text, 'html.parser')
        blockquotes = soup.find_all('span', class_='blockquote')
        for bq in blockquotes:
            bq_content = bq.get_text()
            bq.replace_with(f"```\n{bq_content}\n```")
        return str(soup)

    def _remove_footer(self,text):
        """Removes the footer from html content
            Args:
                text: html content text
            Returns:
                processed Beautiful soup object
            """
        soup = BeautifulSoup(text, 'html.parser')

        # Remove footer itself
        footer = soup.find('footer')
        if footer:
            footer.extract()

        return str(soup)


    def _sanitize_text(self,text):
        """Sanitizes the html content
            Args:
                text: html content text
            Returns:
                sanitized html content
            """
        return clean(text, fix_unicode=True, to_ascii=True, lower=False, no_line_breaks=True, no_urls=True,
                    no_emails=False, no_phone_numbers=True, no_numbers=False, no_digits=False,
                    no_currency_symbols=False, no_punct=False, normalize_whitespace=True)

    def _get_p_and_h_tags(self,text):
        """Extracts p and h tagged texts
            Args:
                text: html content text
            Returns:
                extracted and sanitized html content
            """
        soup = BeautifulSoup(text, 'html.parser')
        # If we found the main content, look for "Related Posts" and trim
        if soup:
            related_tag = soup.find(string=lambda s: "Related Posts" in s)
            if related_tag:
                for sibling in related_tag.find_all_next():
                    sibling.extract()
                related_tag.extract()

        filtered_text_list = soup.find_all(['h1', 'h2', 'h3', 'p'])
        filtered_text = [self._sanitize_text(i.get_text()) for i in filtered_text_list]

        return filtered_text


    def preprocess(self,html_text: str):
        """Preprocesses the html content
            Args:
                html_text: html content text
            Returns:
                a filtered text of html content
            """

        # Process blockquote tags
        html_processed = self._process_blockquote_tags(html_text)
        # Remove footer
        html_processed = self._remove_footer(html_processed)

        # Remove the redundant tags
        tags_to_remove_single = ["area", "script", "base", "meta", "link"]
        tags_to_remove_double = ["head", "footer", "nav", "style", "aside", "iframe", "object", "svg", "form", "button",
                                "label", "input", "select", "textarea", "video", "audio", "canvas", "applet", "embed",
                                "frame", "frameset", "script", "noscript", "progress", "source", "track", "meter",
                                "keygen", "datalist"]

        for tag in tags_to_remove_double:
            html_processed = re.sub(r'<' + tag + r'[^>]*>.*?</' + tag + r'>', '', html_processed)
        for tag in tags_to_remove_single:
            html_processed = re.sub(r'<' + tag + r'[^>]*>', '', html_processed)

        filtered_text = self._get_p_and_h_tags(html_processed)
        print("Result of crawling report page:")
        text_joined='\n'.join(filtered_text)
        print('\n'.join(filtered_text))
        if len (text_joined) <= 250:
            raise PreprocessingException("Report content is too short ({})".format(len(text_joined)))
        return ' \n'.join(filtered_text)


class PreprocessingException(Exception):
    """Raised when preprocessing fails"""
    def __init__(self, message) -> None:
        super().__init__(message)

