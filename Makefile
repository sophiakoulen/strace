CC = gcc
CFLAGS = -Wall -Wextra

NAME = ft_strace
SRCS = src/main.c

all: $(NAME)

$(NAME): $(SRCS)
	$(CC) $(CFLAGS) -o $(NAME) $(SRCS)

clean:

fclean: clean
	rm -f $(NAME)

re: fclean all
